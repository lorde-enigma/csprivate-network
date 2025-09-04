#pragma once

#include "core/types.h"
#include "domain/repository.h"
#include "domain/services.h"
#include <memory>
#include <string>
#include <vector>

namespace openvpn_manager {

class CreateVPNUseCase {
public:
    CreateVPNUseCase(
        std::shared_ptr<VPNRepository> repository,
        std::shared_ptr<CertificateService> cert_service,
        std::shared_ptr<NetworkService> network_service,
        std::shared_ptr<SystemService> system_service,
        std::shared_ptr<ConfigurationService> config_service
    );
    
    bool execute(const VPNConfig& config, const ClientConfig& initial_client);

private:
    std::shared_ptr<VPNRepository> repository_;
    std::shared_ptr<CertificateService> cert_service_;
    std::shared_ptr<NetworkService> network_service_;
    std::shared_ptr<SystemService> system_service_;
    std::shared_ptr<ConfigurationService> config_service_;
};

class AddClientUseCase {
public:
    AddClientUseCase(
        std::shared_ptr<VPNRepository> repository,
        std::shared_ptr<CertificateService> cert_service,
        std::shared_ptr<ConfigurationService> config_service
    );
    
    bool execute(const std::string& vpn_name, const ClientConfig& client_config);

private:
    std::shared_ptr<VPNRepository> repository_;
    std::shared_ptr<CertificateService> cert_service_;
    std::shared_ptr<ConfigurationService> config_service_;
};

class RevokeClientUseCase {
public:
    RevokeClientUseCase(
        std::shared_ptr<VPNRepository> repository,
        std::shared_ptr<CertificateService> cert_service
    );
    
    bool execute(const std::string& vpn_name, const std::string& client_name);

private:
    std::shared_ptr<VPNRepository> repository_;
    std::shared_ptr<CertificateService> cert_service_;
};

class RemoveVPNUseCase {
public:
    RemoveVPNUseCase(
        std::shared_ptr<VPNRepository> repository,
        std::shared_ptr<NetworkService> network_service,
        std::shared_ptr<SystemService> system_service
    );
    
    bool execute(const std::string& vpn_name);

private:
    std::shared_ptr<VPNRepository> repository_;
    std::shared_ptr<NetworkService> network_service_;
    std::shared_ptr<SystemService> system_service_;
};

class ListVPNsUseCase {
public:
    ListVPNsUseCase(
        std::shared_ptr<VPNRepository> repository,
        std::shared_ptr<SystemService> system_service
    );
    
    std::vector<VPNConfig> execute();

private:
    std::shared_ptr<VPNRepository> repository_;
    std::shared_ptr<SystemService> system_service_;
};

class ManageServiceUseCase {
public:
    ManageServiceUseCase(std::shared_ptr<SystemService> system_service);
    
    bool start_vpn(const std::string& vpn_name);
    bool stop_vpn(const std::string& vpn_name);
    bool restart_vpn(const std::string& vpn_name);
    bool get_status(const std::string& vpn_name);

private:
    std::shared_ptr<SystemService> system_service_;
};

}
