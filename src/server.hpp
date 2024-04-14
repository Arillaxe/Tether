#include <string>
#include <openssl/ssl.h>

#include "logger.hpp"

namespace Tether {
  typedef void (*OnConnectCallback)();
  typedef void (*OnMessageCallback)(char* data, int size);

  class Server {
  public:
    Server(const char* name, bool secure, const char* certPath, const char* keyPath);
    ~Server();

    void listen(const char* host, int port, const char* subProtocol);
    void listen(const char* host, int port);
    void listen(int port);

    void onConnect(OnConnectCallback callback);
    void onMessage(OnMessageCallback callback);

    int send(char* data, unsigned int size);
  private:
    OnConnectCallback onConnectCallback;
    OnMessageCallback onMessageCallback;
    int port;
    std::string host;
    std::string subProtocol;

    Logger logger;

    SSL_CTX* ssl_ctx = nullptr;

    void initSSL(const char* certPath, const char* keyPath); 
  };
}
