#include "server.hpp"

namespace Tether {
  Server::Server(const char* name, bool secure, const char* certPath, const char* keyPath)
  : logger(name) {
    if (secure) {
      if (certPath == NULL || keyPath == NULL) {
        logger.log(LogLevel::ERROR, "certPath and keyPath is required for secure mode");
        exit(1);
      }

      initSSL(certPath, keyPath);
    }

    logger.log("Server initialized");
  }

  void Server::initSSL(const char* certPath, const char* keyPath) {
    if (SSL_library_init() <= 0) {
      logger.log(LogLevel::ERROR, "Can't initialize SSL");
      exit(1);
    }
    if (OpenSSL_add_all_algorithms() <= 0) {
      logger.log(LogLevel::ERROR, "Can't add SSL algorithms");
      exit(1);
    }
    if (SSL_load_error_strings() <= 0) {
      logger.log(LogLevel::ERROR, "Can't load SSL error strings");
      exit(1);
    }
    if (SSL_library_init() <= 0) {
      logger.log(LogLevel::ERROR, "Can't initialize SSL");
      exit(1);
    }
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx == nullptr) {
      logger.log(LogLevel::ERROR, "Can't create SSL context");
      exit(1);
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, certPath, SSL_FILETYPE_PEM) <= 0) {
      logger.log(LogLevel::ERROR, "Unable to load cert at path: " + std::string(certPath));
      exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyPath, SSL_FILETYPE_PEM) <= 0) {
      logger.log(LogLevel::ERROR, "Unable to load key at path: " + std::string(certPath));
      exit(1);
    }
    logger.log("SSL initialized");
  }

  Server::~Server() {
    logger.log("Server destruct");
  }

  void Server::onConnect(OnConnectCallback callback) {
    onConnectCallback = callback;
  }

  void Server::onMessage(OnMessageCallback callback) {
    onMessageCallback = callback;
  }
}
