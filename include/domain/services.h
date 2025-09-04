#pragma once

#include "core/types.h"
#include "domain/repository.h"
#include <memory>

namespace openvpn_manager {

class CertificateService {
public:
    virtual ~CertificateService() = default;
    
    virtual bool initialize_pki(const std::string& vpn_name) = 0;
    virtual bool generate_ca_certificate(const std::string& vpn_name) = 0;
    virtual bool generate_server_certificate(const std::string& vpn_name) = 0;
    virtual bool generate_client_certificate(const std::string& vpn_name, const std::string& client_name) = 0;
    virtual bool revoke_client_certificate(const std::string& vpn_name, const std::string& client_name) = 0;
    virtual bool generate_crl(const std::string& vpn_name) = 0;
    virtual bool generate_tls_crypt_key(const std::string& vpn_name) = 0;
    virtual bool generate_dh_params(const std::string& vpn_name) = 0;
};

class NetworkService {
public:
    virtual ~NetworkService() = default;
    
    virtual NetworkConfig detect_network_configuration() = 0;
    virtual uint16_t get_next_available_subnet() = 0;
    virtual uint16_t get_next_available_port() = 0;
    virtual bool enable_ip_forwarding() = 0;
    virtual bool configure_firewall(const VPNConfig& config) = 0;
    virtual bool remove_firewall_rules(const VPNConfig& config) = 0;
};

class SystemService {
public:
    virtual ~SystemService() = default;
    
    virtual bool install_dependencies() = 0;
    virtual bool create_systemd_service(const std::string& vpn_name) = 0;
    virtual bool start_service(const std::string& vpn_name) = 0;
    virtual bool stop_service(const std::string& vpn_name) = 0;
    virtual bool enable_service(const std::string& vpn_name) = 0;
    virtual bool disable_service(const std::string& vpn_name) = 0;
    virtual bool is_service_active(const std::string& vpn_name) = 0;
    virtual bool remove_service(const std::string& vpn_name) = 0;
};

class ConfigurationService {
public:
    virtual ~ConfigurationService() = default;
    
    virtual bool generate_server_config(const VPNConfig& config) = 0;
    virtual bool generate_client_config(const std::string& vpn_name, const std::string& client_name) = 0;
    virtual bool generate_client_template(const VPNConfig& config) = 0;
    virtual std::string get_client_config_path(const std::string& vpn_name, const std::string& client_name) = 0;
};

}
