#include <iostream>
#include <fstream>
#include <ctime>

enum class LogLevel { INFO, WARNING, ERROR };

namespace Tether {
  class Logger {
  public:
    Logger(const std::string& name) : m_filename(name + ".txt"), m_name(name) {
      m_file.open(m_filename);
      if (!m_file.is_open()) {
        std::cerr << "Error: Could not open log file: " << m_filename << std::endl;
      }
    }

    ~Logger() {
      if (m_file.is_open()) {
        m_file.close();
      }
    }

    void log(const std::string& message) {
      std::string timestamp = getTimestamp();
      std::string levelStr = "INFO";
      if (m_file.is_open()) {
          m_file << "[" << timestamp << "] " << "[" << levelStr << "] " << message << std::endl;
        }
        std::cout << "[" << m_name  << "]" << "[" << timestamp << "] " << "[" << levelStr << "] " << message << std::endl;
    }

    void log(LogLevel level, const std::string& message) {
      std::string timestamp = getTimestamp();
      std::string levelStr;
        switch (level) {
          case LogLevel::INFO:
            levelStr = "INFO";
            break;
          case LogLevel::WARNING:
            levelStr = "WARNING";
            break;
          case LogLevel::ERROR:
            levelStr = "ERROR";
            break;
        }
        if (m_file.is_open()) {
          m_file << "[" << timestamp << "] " << "[" << levelStr << "] " << message << std::endl;
        }
        std::cout << "[" << m_name  << "]" << "[" << timestamp << "] " << "[" << levelStr << "] " << message << std::endl;
      }

  private:
    std::string getTimestamp() {
      std::time_t now = std::time(nullptr);
      char buffer[80];
      std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
      return buffer;
    }

    std::ofstream m_file;
    std::string m_filename;
    std::string m_name;
  };
}
