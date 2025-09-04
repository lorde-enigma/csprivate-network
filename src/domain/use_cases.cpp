#include "domain/use_cases.h"
#include "infrastructure/interfaces.h"

namespace openvpn_manager {

CreateVPNUseCase::CreateVPNUseCase(
    std::shared_ptr<VPNRepository> repository,
    std::shared_ptr<CertificateService> cert_service,
    std::shared_ptr<NetworkService> network_service,
    std::shared_ptr<SystemService> system_service,
    std::shared_ptr<ConfigurationService> config_service
) : repository_(repository),
    cert_service_(cert_service),
    network_service_(network_service),
    system_service_(system_service),
    config_service_(config_service) {}

bool CreateVPNUseCase::execute(const VPNConfig& config, const std::string& initial_client_name) {
    if (repository_->vpn_exists(config.name)) {
        return false;
    }
    
    VPNConfig working_config = config;
    working_config.server_dir = "/etc/openvpn/server-" + working_config.name;
    working_config.easyrsa_dir = working_config.server_dir + "/easy-rsa";
    
    if (!repository_->create_vpn_config(working_config)) {
        return false;
    }
    
    if (!cert_service_->initialize_pki(working_config.name)) {
        return false;
    }
    
    if (!cert_service_->generate_ca_certificate(working_config.name)) {
        return false;
    }
    
    if (!cert_service_->generate_server_certificate(working_config.name)) {
        return false;
    }
    
    if (!cert_service_->generate_client_certificate(working_config.name, initial_client_name)) {
        return false;
    }
    
    if (!cert_service_->generate_crl(working_config.name)) {
        return false;
    }
    
    if (!cert_service_->generate_tls_crypt_key(working_config.name)) {
        return false;
    }
    
    if (!cert_service_->generate_dh_params(working_config.name)) {
        return false;
    }
    
    if (!config_service_->generate_server_config(working_config)) {
        return false;
    }
    
    if (!config_service_->generate_client_template(working_config)) {
        return false;
    }
    
    if (!config_service_->generate_client_config(working_config.name, initial_client_name)) {
        return false;
    }
    
    if (!network_service_->enable_ip_forwarding()) {
        return false;
    }
    
    if (!network_service_->configure_firewall(working_config)) {
        return false;
    }
    
    if (!system_service_->create_systemd_service(working_config.name)) {
        return false;
    }
    
    if (!system_service_->enable_service(working_config.name)) {
        return false;
    }
    
    if (!system_service_->start_service(working_config.name)) {
        return false;
    }
    
    ClientConfig client_config;
    client_config.name = initial_client_name;
    client_config.vpn_name = working_config.name;
    client_config.is_revoked = false;
    
    return repository_->add_client(working_config.name, client_config);
}

AddClientUseCase::AddClientUseCase(
    std::shared_ptr<VPNRepository> repository,
    std::shared_ptr<CertificateService> cert_service,
    std::shared_ptr<ConfigurationService> config_service
) : repository_(repository),
    cert_service_(cert_service),
    config_service_(config_service) {}

bool AddClientUseCase::execute(const std::string& vpn_name, const std::string& client_name) {
    if (!repository_->vpn_exists(vpn_name)) {
        return false;
    }
    
    if (repository_->client_exists(vpn_name, client_name)) {
        return false;
    }
    
    if (!cert_service_->generate_client_certificate(vpn_name, client_name)) {
        return false;
    }
    
    if (!config_service_->generate_client_config(vpn_name, client_name)) {
        return false;
    }
    
    ClientConfig client_config;
    client_config.name = client_name;
    client_config.vpn_name = vpn_name;
    client_config.is_revoked = false;
    
    return repository_->add_client(vpn_name, client_config);
}

RevokeClientUseCase::RevokeClientUseCase(
    std::shared_ptr<VPNRepository> repository,
    std::shared_ptr<CertificateService> cert_service
) : repository_(repository),
    cert_service_(cert_service) {}

bool RevokeClientUseCase::execute(const std::string& vpn_name, const std::string& client_name) {
    if (!repository_->vpn_exists(vpn_name)) {
        return false;
    }
    
    if (!repository_->client_exists(vpn_name, client_name)) {
        return false;
    }
    
    if (!cert_service_->revoke_client_certificate(vpn_name, client_name)) {
        return false;
    }
    
    if (!cert_service_->generate_crl(vpn_name)) {
        return false;
    }
    
    return repository_->revoke_client(vpn_name, client_name);
}

RemoveVPNUseCase::RemoveVPNUseCase(
    std::shared_ptr<VPNRepository> repository,
    std::shared_ptr<NetworkService> network_service,
    std::shared_ptr<SystemService> system_service
) : repository_(repository),
    network_service_(network_service),
    system_service_(system_service) {}

bool RemoveVPNUseCase::execute(const std::string& vpn_name) {
    auto config_opt = repository_->get_vpn_config(vpn_name);
    if (!config_opt.has_value()) {
        return false;
    }
    
    auto config = config_opt.value();
    
    system_service_->stop_service(vpn_name);
    system_service_->disable_service(vpn_name);
    system_service_->remove_service(vpn_name);
    
    network_service_->remove_firewall_rules(config);
    
    return repository_->delete_vpn_config(vpn_name);
}

ListVPNsUseCase::ListVPNsUseCase(
    std::shared_ptr<VPNRepository> repository,
    std::shared_ptr<SystemService> system_service
) : repository_(repository),
    system_service_(system_service) {}

std::vector<VPNConfig> ListVPNsUseCase::execute() {
    return repository_->get_all_vpn_configs();
}

ManageServiceUseCase::ManageServiceUseCase(std::shared_ptr<SystemService> system_service)
    : system_service_(system_service) {}

bool ManageServiceUseCase::start_vpn(const std::string& vpn_name) {
    return system_service_->start_service(vpn_name);
}

bool ManageServiceUseCase::stop_vpn(const std::string& vpn_name) {
    return system_service_->stop_service(vpn_name);
}

bool ManageServiceUseCase::restart_vpn(const std::string& vpn_name) {
    return system_service_->stop_service(vpn_name) && 
           system_service_->start_service(vpn_name);
}

bool ManageServiceUseCase::get_status(const std::string& vpn_name) {
    return system_service_->is_service_active(vpn_name);
}

}
