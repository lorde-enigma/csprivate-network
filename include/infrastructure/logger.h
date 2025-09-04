#pragma once

#include "infrastructure/interfaces.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace openvpn_manager {

class ConsoleLogger : public Logger {
public:
    void log(LogLevel level, const std::string& message) override {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                  << level_to_string(level) << ": " << message << std::endl;
    }
    
    void debug(const std::string& message) override {
        log(LogLevel::DEBUG, message);
    }
    
    void info(const std::string& message) override {
        log(LogLevel::INFO, message);
    }
    
    void warning(const std::string& message) override {
        log(LogLevel::WARNING, message);
    }
    
    void error(const std::string& message) override {
        log(LogLevel::ERROR, message);
    }

private:
    std::string level_to_string(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "debug";
            case LogLevel::INFO: return "info";
            case LogLevel::WARNING: return "warning";
            case LogLevel::ERROR: return "error";
            default: return "unknown";
        }
    }
};

class FileLogger : public Logger {
public:
    explicit FileLogger(const std::string& log_file_path) 
        : log_file_path_(log_file_path) {}
    
    void log(LogLevel level, const std::string& message) override {
        std::ofstream log_file(log_file_path_, std::ios::app);
        if (log_file.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            
            log_file << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                     << level_to_string(level) << ": " << message << std::endl;
        }
    }
    
    void debug(const std::string& message) override {
        log(LogLevel::DEBUG, message);
    }
    
    void info(const std::string& message) override {
        log(LogLevel::INFO, message);
    }
    
    void warning(const std::string& message) override {
        log(LogLevel::WARNING, message);
    }
    
    void error(const std::string& message) override {
        log(LogLevel::ERROR, message);
    }

private:
    std::string log_file_path_;
    
    std::string level_to_string(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "debug";
            case LogLevel::INFO: return "info";
            case LogLevel::WARNING: return "warning";
            case LogLevel::ERROR: return "error";
            default: return "unknown";
        }
    }
};

}
