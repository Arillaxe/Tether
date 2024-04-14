#include <sys/socket.h>
#include <netinet/in.h>

#include "logger.hpp"

namespace Tether {
  class TCPServer {
    TCPServer(int port, Logger& logger) {
      struct sockaddr_in serverAddr, clientAddr;
      socklen_t clientAddrLen = sizeof(clientAddr);
      int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
      if (serverSocket < 0) {
        logger.log(LogLevel::ERROR, "Error creating server socket");
        exit(1);
      }

      memset(&serverAddr, 0, sizeof(serverAddr));
      serverAddr.sin_family = AF_INET;
      serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
      serverAddr.sin_port = htons(port);

      if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        logger.log(LogLevel::ERROR, "Error binding server socket at port: " + port);
        exit(1);
      }

      if (listen(serverSocket, 10) < 0) {
        logger.log(LogLevel::ERROR, "Error listening on server socket");
        exit(1);
      }

      // TODO: launch tcp listening thread
    }
  };
}
