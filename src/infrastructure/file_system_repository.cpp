#include "infrastructure/file_system_repository.h"
#include <sstream>
#include <algorithm>
#include <regex>

namespace openvpn_manager {

FileSystemVPNRepository::FileSystemVPNRepository(
    std::shared_ptr<FileSystem> file_system,
    std::shared_ptr<Logger> logger,
    const std::string& config_base_path
) : file_system_(file_system),
    logger_(logger),
    config_base_path_(config_base_path) {}

bool FileSystemVPNRepository::create_vpn_config(const VPNConfig& config) {
    std::string vpn_dir = get_vpn_directory(config.name);
    
    if (!file_system_->create_directory(vpn_dir, true)) {
        logger_->error("failed to create vpn directory: " + vpn_dir);
        return false;
    }
    
    logger_->info("created vpn configuration directory for: " + config.name);
    return true;
}

bool FileSystemVPNRepository::update_vpn_config(const VPNConfig& config) {
    if (!vpn_exists(config.name)) {
        logger_->error("vpn configuration does not exist: " + config.name);
        return false;
    }
    
    logger_->info("updated vpn configuration: " + config.name);
    return true;
}

bool FileSystemVPNRepository::delete_vpn_config(const std::string& name) {
    std::string vpn_dir = get_vpn_directory(name);
    
    if (!file_system_->directory_exists(vpn_dir)) {
        logger_->warning("vpn directory does not exist: " + vpn_dir);
        return false;
    }
    
    if (!file_system_->remove_directory(vpn_dir)) {
        logger_->error("failed to remove vpn directory: " + vpn_dir);
        return false;
    }
    
    logger_->info("removed vpn configuration: " + name);
    return true;
}

std::optional<VPNConfig> FileSystemVPNRepository::get_vpn_config(const std::string& name) {
    std::string config_path = get_server_config_path(name);
    
    if (!file_system_->file_exists(config_path)) {
        logger_->debug("vpn config file not found: " + config_path);
        return std::nullopt;
    }
    
    std::string config_content = file_system_->read_file(config_path);
    if (config_content.empty()) {
        logger_->error("failed to read vpn config file: " + config_path);
        return std::nullopt;
    }
    
    return parse_server_config(config_content, name);
}

std::vector<VPNConfig> FileSystemVPNRepository::get_all_vpn_configs() {
    std::vector<VPNConfig> configs;
    
    if (!file_system_->directory_exists(config_base_path_)) {
        logger_->debug("config base path does not exist: " + config_base_path_);
        return configs;
    }
    
    auto directories = file_system_->list_directory(config_base_path_);
    
    for (const auto& dir : directories) {
        if (dir.find("server-") == 0) {
            std::string vpn_name = dir.substr(7);
            auto config_opt = get_vpn_config(vpn_name);
            if (config_opt.has_value()) {
                configs.push_back(config_opt.value());
            }
        }
    }
    
    logger_->debug("found " + std::to_string(configs.size()) + " vpn configurations");
    return configs;
}

bool FileSystemVPNRepository::add_client(const std::string& vpn_name, const ClientConfig& client) {
    if (!vpn_exists(vpn_name)) {
        logger_->error("vpn does not exist: " + vpn_name);
        return false;
    }
    
    logger_->info("added client " + client.name + " to vpn " + vpn_name);
    return true;
}

bool FileSystemVPNRepository::revoke_client(const std::string& vpn_name, const std::string& client_name) {
    if (!vpn_exists(vpn_name)) {
        logger_->error("vpn does not exist: " + vpn_name);
        return false;
    }
    
    if (!client_exists(vpn_name, client_name)) {
        logger_->error("client does not exist: " + client_name);
        return false;
    }
    
    logger_->info("revoked client " + client_name + " from vpn " + vpn_name);
    return true;
}

std::vector<ClientConfig> FileSystemVPNRepository::get_clients(const std::string& vpn_name) {
    std::vector<ClientConfig> clients;
    
    std::string vpn_dir = get_vpn_directory(vpn_name);
    std::string index_file = vpn_dir + "/easy-rsa/pki/index.txt";
    
    if (!file_system_->file_exists(index_file)) {
        logger_->debug("index file not found: " + index_file);
        return clients;
    }
    
    std::string content = file_system_->read_file(index_file);
    std::istringstream stream(content);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == 'V' || line[0] == 'R') {
            std::regex pattern(R"(/CN=([^/]+))");
            std::smatch matches;
            
            if (std::regex_search(line, matches, pattern)) {
                ClientConfig client;
                client.name = matches[1].str();
                client.vpn_name = vpn_name;
                client.is_revoked = (line[0] == 'R');
                client.use_route_nopull = true;
                clients.push_back(client);
            }
        }
    }
    
    logger_->debug("found " + std::to_string(clients.size()) + " clients for vpn " + vpn_name);
    return clients;
}

bool FileSystemVPNRepository::vpn_exists(const std::string& name) {
    std::string vpn_dir = get_vpn_directory(name);
    return file_system_->directory_exists(vpn_dir);
}

bool FileSystemVPNRepository::client_exists(const std::string& vpn_name, const std::string& client_name) {
    std::string cert_file = get_vpn_directory(vpn_name) + "/easy-rsa/pki/issued/" + client_name + ".crt";
    return file_system_->file_exists(cert_file);
}

std::string FileSystemVPNRepository::get_vpn_directory(const std::string& vpn_name) {
    return config_base_path_ + "/server-" + vpn_name;
}

std::string FileSystemVPNRepository::get_server_config_path(const std::string& vpn_name) {
    return get_vpn_directory(vpn_name) + "/server.conf";
}

std::string FileSystemVPNRepository::get_client_template_path(const std::string& vpn_name) {
    return get_vpn_directory(vpn_name) + "/client-common.txt";
}

VPNConfig FileSystemVPNRepository::parse_server_config(const std::string& config_content, const std::string& vpn_name) {
    VPNConfig config;
    config.name = vpn_name;
    config.server_dir = get_vpn_directory(vpn_name);
    config.easyrsa_dir = config.server_dir + "/easy-rsa";
    
    std::istringstream stream(config_content);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.find("port ") == 0) {
            config.port = static_cast<uint16_t>(std::stoi(line.substr(5)));
        } else if (line.find("proto ") == 0) {
            std::string proto = line.substr(6);
            config.protocol = (proto == "tcp") ? Protocol::TCP : Protocol::UDP;
        } else if (line.find("local ") == 0) {
            config.network.ipv4_address = line.substr(6);
        } else if (line.find("server ") == 0) {
            std::string subnet_line = line.substr(7);
            auto space_pos = subnet_line.find(' ');
            if (space_pos != std::string::npos) {
                config.network.subnet_address = subnet_line.substr(0, space_pos);
                auto dot_pos = config.network.subnet_address.find_last_of('.');
                if (dot_pos != std::string::npos) {
                    auto third_dot = config.network.subnet_address.find_last_of('.', dot_pos - 1);
                    if (third_dot != std::string::npos) {
                        std::string subnet_str = config.network.subnet_address.substr(third_dot + 1, dot_pos - third_dot - 1);
                        config.network.subnet_number = static_cast<uint16_t>(std::stoi(subnet_str));
                    }
                }
            }
        }
    }
    
    return config;
}

std::string FileSystemVPNRepository::serialize_vpn_config(const VPNConfig& config) {
    std::ostringstream oss;
    oss << "name=" << config.name << "\n";
    oss << "port=" << config.port << "\n";
    oss << "protocol=" << (config.protocol == Protocol::TCP ? "tcp" : "udp") << "\n";
    oss << "ipv4=" << config.network.ipv4_address << "\n";
    oss << "subnet_address=" << config.network.subnet_address << "\n";
    return oss.str();
}

}
