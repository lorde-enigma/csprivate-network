#pragma once

#include "infrastructure/interfaces.h"

namespace openvpn_manager {

class LinuxFileSystem : public FileSystem {
public:
    bool create_directory(const std::string& path, bool recursive = true) override;
    bool directory_exists(const std::string& path) override;
    bool file_exists(const std::string& path) override;
    bool remove_directory(const std::string& path) override;
    bool remove_file(const std::string& path) override;
    std::string read_file(const std::string& path) override;
    bool write_file(const std::string& path, const std::string& content) override;
    std::vector<std::string> list_directory(const std::string& path) override;
    bool copy_file(const std::string& source, const std::string& destination) override;
};

class LinuxProcessExecutor : public ProcessExecutor {
public:
    ExecutionResult execute(const std::string& command) override;
    ExecutionResult execute(const std::vector<std::string>& args) override;
    bool execute_async(const std::string& command) override;
};

class LinuxSystemDetector : public SystemDetector {
public:
    OSType detect_os() override;
    std::string get_os_version() override;
    bool is_systemd_available() override;
    bool is_firewalld_active() override;
    bool has_ipv6_support() override;
    bool is_running_as_root() override;
    bool has_tun_device() override;
};

}
