#pragma once

#include "domain/use_cases.h"
#include "infrastructure/interfaces.h"
#include <memory>
#include <string>
#include <utility>

namespace openvpn_manager {

class CLIController {
public:
    CLIController(
        std::shared_ptr<CreateVPNUseCase> create_vpn_use_case,
        std::shared_ptr<AddClientUseCase> add_client_use_case,
        std::shared_ptr<RevokeClientUseCase> revoke_client_use_case,
        std::shared_ptr<RemoveVPNUseCase> remove_vpn_use_case,
        std::shared_ptr<ListVPNsUseCase> list_vpns_use_case,
        std::shared_ptr<ManageServiceUseCase> manage_service_use_case,
        std::shared_ptr<NetworkService> network_service,
        std::shared_ptr<Logger> logger
    );
    
    void run();

private:
    std::shared_ptr<CreateVPNUseCase> create_vpn_use_case_;
    std::shared_ptr<AddClientUseCase> add_client_use_case_;
    std::shared_ptr<RevokeClientUseCase> revoke_client_use_case_;
    std::shared_ptr<RemoveVPNUseCase> remove_vpn_use_case_;
    std::shared_ptr<ListVPNsUseCase> list_vpns_use_case_;
    std::shared_ptr<ManageServiceUseCase> manage_service_use_case_;
    std::shared_ptr<NetworkService> network_service_;
    std::shared_ptr<Logger> logger_;
    
    void show_main_menu();
    void handle_create_vpn();
    void handle_manage_vpn();
    void handle_list_vpns();
    void handle_service_status();
    
    VPNConfig collect_vpn_configuration();
    std::string collect_vpn_name();
    std::string collect_client_name();
    ClientConfig collect_client_info();
    std::string collect_host_ip();
    Protocol collect_protocol();
    uint16_t collect_port();
    std::pair<std::string, uint16_t> collect_subnet_address();
    DNSProvider collect_dns_provider();
    
    std::string sanitize_name(const std::string& name);
    void clear_screen();
    void wait_for_enter();
    std::string get_user_input(const std::string& prompt);
    int get_user_choice(const std::string& prompt, int min_value, int max_value);
    bool get_user_confirmation(const std::string& prompt);
};

}
