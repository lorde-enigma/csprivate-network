#pragma once

#include <string>
#include <vector>
#include <memory>

namespace openvpn_manager {

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

class Logger {
public:
    virtual ~Logger() = default;
    
    virtual void log(LogLevel level, const std::string& message) = 0;
    virtual void debug(const std::string& message) = 0;
    virtual void info(const std::string& message) = 0;
    virtual void warning(const std::string& message) = 0;
    virtual void error(const std::string& message) = 0;
};

class FileSystem {
public:
    virtual ~FileSystem() = default;
    
    virtual bool create_directory(const std::string& path, bool recursive = true) = 0;
    virtual bool remove_directory(const std::string& path) = 0;
    virtual bool file_exists(const std::string& path) = 0;
    virtual bool directory_exists(const std::string& path) = 0;
    virtual bool copy_file(const std::string& source, const std::string& destination) = 0;
    virtual bool remove_file(const std::string& path) = 0;
    virtual bool write_file(const std::string& path, const std::string& content) = 0;
    virtual std::string read_file(const std::string& path) = 0;
    virtual std::vector<std::string> list_directory(const std::string& path) = 0;
};

class ProcessExecutor {
public:
    virtual ~ProcessExecutor() = default;
    
    struct ExecutionResult {
        int exit_code;
        std::string stdout_output;
        std::string stderr_output;
    };
    
    virtual ExecutionResult execute(const std::string& command) = 0;
    virtual ExecutionResult execute(const std::vector<std::string>& args) = 0;
    virtual bool execute_async(const std::string& command) = 0;
};

class SystemDetector {
public:
    virtual ~SystemDetector() = default;
    
    enum class OSType {
        UBUNTU,
        DEBIAN,
        CENTOS,
        FEDORA,
        UNKNOWN
    };
    
    virtual OSType detect_os() = 0;
    virtual std::string get_os_version() = 0;
    virtual bool is_systemd_available() = 0;
    virtual bool is_firewalld_active() = 0;
    virtual bool has_ipv6_support() = 0;
    virtual bool is_running_as_root() = 0;
    virtual bool has_tun_device() = 0;
};

}
