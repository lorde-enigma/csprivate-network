#pragma once

#include "domain/repository.h"
#include "infrastructure/interfaces.h"
#include <memory>

namespace openvpn_manager {

class FileSystemVPNRepository : public VPNRepository {
public:
    FileSystemVPNRepository(
        std::shared_ptr<FileSystem> file_system,
        std::shared_ptr<Logger> logger,
        const std::string& config_base_path = "/etc/openvpn"
    );
    
    bool create_vpn_config(const VPNConfig& config) override;
    bool update_vpn_config(const VPNConfig& config) override;
    bool delete_vpn_config(const std::string& name) override;
    std::optional<VPNConfig> get_vpn_config(const std::string& name) override;
    std::vector<VPNConfig> get_all_vpn_configs() override;
    
    bool add_client(const std::string& vpn_name, const ClientConfig& client) override;
    bool revoke_client(const std::string& vpn_name, const std::string& client_name) override;
    std::vector<ClientConfig> get_clients(const std::string& vpn_name) override;
    
    bool vpn_exists(const std::string& name) override;
    bool client_exists(const std::string& vpn_name, const std::string& client_name) override;

private:
    std::shared_ptr<FileSystem> file_system_;
    std::shared_ptr<Logger> logger_;
    std::string config_base_path_;
    
    std::string get_vpn_directory(const std::string& vpn_name);
    std::string get_server_config_path(const std::string& vpn_name);
    std::string get_client_template_path(const std::string& vpn_name);
    VPNConfig parse_server_config(const std::string& config_content, const std::string& vpn_name);
    std::string serialize_vpn_config(const VPNConfig& config);
};

}
