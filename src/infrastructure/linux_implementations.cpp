#include "infrastructure/linux_implementations.h"
#include "infrastructure/logger.h"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace openvpn_manager {

bool LinuxFileSystem::create_directory(const std::string& path, bool recursive) {
    std::error_code ec;
    if (recursive) {
        return std::filesystem::create_directories(path, ec);
    } else {
        return std::filesystem::create_directory(path, ec);
    }
}

bool LinuxFileSystem::directory_exists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::is_directory(path, ec);
}

bool LinuxFileSystem::file_exists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

bool LinuxFileSystem::remove_directory(const std::string& path) {
    std::error_code ec;
    return std::filesystem::remove_all(path, ec) > 0;
}

bool LinuxFileSystem::remove_file(const std::string& path) {
    std::error_code ec;
    return std::filesystem::remove(path, ec);
}

std::string LinuxFileSystem::read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool LinuxFileSystem::write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

std::vector<std::string> LinuxFileSystem::list_directory(const std::string& path) {
    std::vector<std::string> entries;
    std::error_code ec;
    
    for (const auto& entry : std::filesystem::directory_iterator(path, ec)) {
        if (!ec) {
            entries.push_back(entry.path().filename().string());
        }
    }
    
    return entries;
}

bool LinuxFileSystem::copy_file(const std::string& source, const std::string& destination) {
    std::error_code ec;
    return std::filesystem::copy_file(source, destination, ec);
}

ProcessExecutor::ExecutionResult LinuxProcessExecutor::execute(const std::string& command) {
    ProcessExecutor::ExecutionResult result;
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        result.exit_code = -1;
        result.stderr_output = "failed to execute command";
        return result;
    }
    
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result.stdout_output += buffer;
    }
    
    int status = pclose(pipe);
    result.exit_code = WEXITSTATUS(status);
    
    return result;
}

ProcessExecutor::ExecutionResult LinuxProcessExecutor::execute(const std::vector<std::string>& args) {
    if (args.empty()) {
        ProcessExecutor::ExecutionResult result;
        result.exit_code = -1;
        result.stderr_output = "empty command arguments";
        return result;
    }
    
    std::string command = args[0];
    for (size_t i = 1; i < args.size(); ++i) {
        command += " " + args[i];
    }
    
    return execute(command);
}

bool LinuxProcessExecutor::execute_async(const std::string& command) {
    int result = system((command + " &").c_str());
    return result == 0;
}

SystemDetector::OSType LinuxSystemDetector::detect_os() {
    std::ifstream release_file("/etc/os-release");
    if (!release_file.is_open()) {
        return OSType::UNKNOWN;
    }
    
    std::string line;
    while (std::getline(release_file, line)) {
        if (line.find("ID=") == 0) {
            std::string id = line.substr(3);
            if (id.find("ubuntu") != std::string::npos) {
                return OSType::UBUNTU;
            } else if (id.find("debian") != std::string::npos) {
                return OSType::DEBIAN;
            } else if (id.find("centos") != std::string::npos) {
                return OSType::CENTOS;
            } else if (id.find("fedora") != std::string::npos) {
                return OSType::FEDORA;
            }
        }
    }
    
    return OSType::UNKNOWN;
}

std::string LinuxSystemDetector::get_os_version() {
    std::ifstream release_file("/etc/os-release");
    if (!release_file.is_open()) {
        return "unknown";
    }
    
    std::string line;
    while (std::getline(release_file, line)) {
        if (line.find("VERSION_ID=") == 0) {
            std::string version = line.substr(11);
            if (version.front() == '"' && version.back() == '"') {
                version = version.substr(1, version.length() - 2);
            }
            return version;
        }
    }
    
    return "unknown";
}

bool LinuxSystemDetector::is_systemd_available() {
    return std::filesystem::exists("/run/systemd/system");
}

bool LinuxSystemDetector::is_firewalld_active() {
    return system("systemctl is-active --quiet firewalld") == 0;
}

bool LinuxSystemDetector::has_ipv6_support() {
    return std::filesystem::exists("/proc/net/if_inet6");
}

bool LinuxSystemDetector::is_running_as_root() {
    return getuid() == 0;
}

bool LinuxSystemDetector::has_tun_device() {
    return std::filesystem::exists("/dev/net/tun");
}

}
