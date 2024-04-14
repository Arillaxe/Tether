#include "server.hpp"

int main() {
  Tether::Server ws("WebSocket server", true, "localhost.crt", "localhost.key");

  return 0;
}
