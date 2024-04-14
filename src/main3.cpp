#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <csignal>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <memory>

#include "server.hpp"

#define PORT 8081
#define BUFFER_SIZE 1024

#define MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

int serverSocket, clientSocket;
SSL_CTX *ctx;
SSL *ssl = nullptr;

bool cleanupInProgress = false;
void cleanUp(int signal) {
  if (cleanupInProgress) {
    return; // Avoid recursion
  }

  cleanupInProgress = true;

  std::cout << "\nExiting " << signal << "\n";

  // close(clientSocket);
  close(serverSocket);

  exit(signal);
}

std::string getWsKey(std::string payload) {
  std::string key_header = "Sec-WebSocket-Key: ";

  size_t pos = payload.find(key_header);

  if (pos != std::string::npos) {
    return payload.substr(pos + key_header.size(), 24);
  }

  return "NO KEY";
}

void handleWss(SSL* ssl) {
  const int bufferSize = 4096;
  char buffer[bufferSize];

  int bytesRead = SSL_read(ssl, buffer, bufferSize - 1);
  if (bytesRead <= 0) {
    if (bytesRead == 0) {
      std::cout << "WebSocket connection closed by client." << std::endl;
    } else {
      std::cerr << "Error reading from WebSocket." << std::endl;
    }
  }

  buffer[bytesRead] = '\0'; // Null-terminate the received data

  std::string wsKey = getWsKey(buffer);

  if (wsKey == "NO KEY") {
    return;
  }

  wsKey += MAGIC;
  
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char*)wsKey.c_str(), wsKey.size(), hash);

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* mem = BIO_new(BIO_s_mem());
  BIO* bio_chain = BIO_push(b64, mem);
  BIO_write(bio_chain, hash, SHA_DIGEST_LENGTH);
  BIO_flush(bio_chain);

  char* outKey;
  long outKeyLen = BIO_get_mem_data(mem, &outKey);
  std::string outKey_str(outKey);

  std::string upgradeResponse = "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: " + outKey_str + "\r\n";

  int bytesWritten = SSL_write(ssl, upgradeResponse.c_str(), upgradeResponse.size());
  if (bytesWritten <= 0) {
    std::cerr << "Error writing to WebSocket." << std::endl;
  }

  std::cout << "Connection upgraded\n"; 

  while (true) {
    // Read WebSocket frame from the client
    char header[2] = {0};
    bytesRead = SSL_read(ssl, header, 2);
    if (bytesRead <= 0) {
      break;
    }
    int payload_size = header[1] & 0x7f;
    printf("Payload length: %d\n", payload_size);

    char masking_key[4] = {0};
    bytesRead = SSL_read(ssl, masking_key, 4);

    std::unique_ptr<char[]> payload_ptr(new char[payload_size + 1]);
    char* payload = payload_ptr.get();
    memset(payload, 0, payload_size + 1);

    bytesRead = SSL_read(ssl, payload, payload_size);
    payload[payload_size + 1] = '\0';

    for (int i = 0; i < payload_size; i++) {
      payload[i] = payload[i] ^ masking_key[i % 4];
    }

    printf("Payload: %s\n", payload);

    // TODO: echo back
    std::unique_ptr<char[]> echoPayload_ptr(new char[payload_size + 2]);
    char* echoPayload = echoPayload_ptr.get();
    memset(echoPayload, 0, payload_size + 2);

    echoPayload[0] |= 0x80; // FIN 1
    echoPayload[0] |= 0x01; // OP CODE 1
    echoPayload[1] |= (payload_size & 0x7f); // payload size
    strcpy(echoPayload + 2, payload);

    SSL_write(ssl, echoPayload, payload_size + 2);
  }
}

void printRawBytes(const char* str, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(str[i])) << " ";
  }
  std::cout << std::endl;
}

int main3() {
  signal(SIGINT, cleanUp);
  signal(SIGABRT, cleanUp);
  signal(SIGSEGV, cleanUp);

  struct sockaddr_in serverAddr, clientAddr;
  socklen_t clientAddrLen = sizeof(clientAddr);

  // Initialize OpenSSL
  int ssl_init = SSL_library_init();
  std::cout << ssl_init << "\n";
  ssl_init = OpenSSL_add_all_algorithms();
  std::cout << ssl_init << "\n";
  ssl_init = SSL_load_error_strings();
  std::cout << ssl_init << "\n";
  ctx = SSL_CTX_new(TLS_server_method());

  // Load server certificate and private key
  printf("%d\n", SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM));
  printf("%d\n", SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM));

  // Create a TCP socket
  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    std::cerr << "Error creating server socket" << std::endl;
    return 1;
  }

  // Bind socket to port
  memset(&serverAddr, 0, sizeof(serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serverAddr.sin_port = htons(PORT);
  if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    std::cerr << "Error binding server socket" << std::endl;
    return 1;
  }

  // Listen for incoming connections
  if (listen(serverSocket, 10) < 0) {
    std::cerr << "Error listening on server socket" << std::endl;
    return 1;
  }

  std::cout << "Server listening on port " << PORT << std::endl;

  // Accept incoming connections
  while (true) {
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (clientSocket < 0) {
      std::cerr << "Error accepting connection" << std::endl;
      continue;
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    ssl_init = SSL_set_fd(ssl, clientSocket);
    std::cout << ssl_init << "\n";

    // Perform SSL handshake
    int ssl_handshake = SSL_accept(ssl);
    if (ssl_handshake <= 0) {
      std::cerr << "Error performing SSL handshake " << ssl_handshake << std::endl;
      SSL_free(ssl);
      close(clientSocket);
      continue;
    }

    handleWss(ssl);
    
    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ssl = nullptr;
    close(clientSocket);
  }

  // Clean up
  close(serverSocket);
  SSL_CTX_free(ctx);
  return 0;
}
