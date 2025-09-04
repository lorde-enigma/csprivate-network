#pragma once

#include "core/types.h"
#include <vector>
#include <optional>

namespace openvpn_manager {

class VPNRepository {
public:
    virtual ~VPNRepository() = default;
    
    virtual bool create_vpn_config(const VPNConfig& config) = 0;
    virtual bool update_vpn_config(const VPNConfig& config) = 0;
    virtual bool delete_vpn_config(const std::string& name) = 0;
    virtual std::optional<VPNConfig> get_vpn_config(const std::string& name) = 0;
    virtual std::vector<VPNConfig> get_all_vpn_configs() = 0;
    
    virtual bool add_client(const std::string& vpn_name, const ClientConfig& client) = 0;
    virtual bool revoke_client(const std::string& vpn_name, const std::string& client_name) = 0;
    virtual std::vector<ClientConfig> get_clients(const std::string& vpn_name) = 0;
    
    virtual bool vpn_exists(const std::string& name) = 0;
    virtual bool client_exists(const std::string& vpn_name, const std::string& client_name) = 0;
};

}
