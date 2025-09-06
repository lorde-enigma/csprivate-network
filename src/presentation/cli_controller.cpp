#include "presentation/cli_controller.h"
#include "infrastructure/linux_services.h"
#include <iostream>
#include <algorithm>
#include <regex>

namespace openvpn_manager {

CLIController::CLIController(
    std::shared_ptr<CreateVPNUseCase> create_vpn_use_case,
    std::shared_ptr<AddClientUseCase> add_client_use_case,
    std::shared_ptr<RevokeClientUseCase> revoke_client_use_case,
    std::shared_ptr<RemoveVPNUseCase> remove_vpn_use_case,
    std::shared_ptr<ListVPNsUseCase> list_vpns_use_case,
    std::shared_ptr<ManageServiceUseCase> manage_service_use_case,
    std::shared_ptr<NetworkService> network_service,
    std::shared_ptr<Logger> logger
) : create_vpn_use_case_(create_vpn_use_case),
    add_client_use_case_(add_client_use_case),
    revoke_client_use_case_(revoke_client_use_case),
    remove_vpn_use_case_(remove_vpn_use_case),
    list_vpns_use_case_(list_vpns_use_case),
    manage_service_use_case_(manage_service_use_case),
    network_service_(network_service),
    logger_(logger) {}

void CLIController::run() {
    logger_->info("starting multi openvpn manager");
    
    while (true) {
        clear_screen();
        show_main_menu();
        
        int choice = get_user_choice("select option", 1, 5);
        
        switch (choice) {
            case 1:
                handle_create_vpn();
                break;
            case 2:
                handle_manage_vpn();
                break;
            case 3:
                handle_list_vpns();
                break;
            case 4:
                handle_service_status();
                break;
            case 5:
                logger_->info("exiting multi openvpn manager");
                return;
        }
        
        wait_for_enter();
    }
}

void CLIController::show_main_menu() {
    std::cout << "=== multi openvpn manager ===\n";
    std::cout << "1) create new vpn\n";
    std::cout << "2) manage existing vpn\n";
    std::cout << "3) list vpn configurations\n";
    std::cout << "4) service status\n";
    std::cout << "5) exit\n";
    std::cout << "\n";
}

void CLIController::handle_create_vpn() {
    clear_screen();
    std::cout << "=== create new vpn ===\n\n";
    
    VPNConfig config = collect_vpn_configuration();
    ClientConfig initial_client = collect_client_info();
    
    std::cout << "\ncreating vpn configuration...\n";
    
    if (create_vpn_use_case_->execute(config, initial_client)) {
        std::cout << "vpn '" << config.name << "' created successfully\n";
        std::cout << "initial client '" << initial_client.name << "' added\n";
        std::cout << "client configuration file: ~/" << config.name << "-" << initial_client.name << ".ovpn\n";
        logger_->info("created vpn: " + config.name + " with client: " + initial_client.name);
    } else {
        std::cout << "failed to create vpn '" << config.name << "'\n";
        logger_->error("failed to create vpn: " + config.name);
    }
}

void CLIController::handle_manage_vpn() {
    clear_screen();
    std::cout << "=== manage existing vpn ===\n\n";
    
    auto vpns = list_vpns_use_case_->execute();
    if (vpns.empty()) {
        std::cout << "no vpn configurations found\n";
        return;
    }
    
    std::cout << "available vpns:\n";
    for (size_t i = 0; i < vpns.size(); ++i) {
        std::cout << (i + 1) << ") " << vpns[i].name 
                  << " - " << (vpns[i].protocol == Protocol::UDP ? "udp" : "tcp")
                  << ":" << vpns[i].port << "\n";
    }
    std::cout << "\n";
    
    int vpn_choice = get_user_choice("select vpn", 1, static_cast<int>(vpns.size()));
    VPNConfig selected_vpn = vpns[vpn_choice - 1];
    
    clear_screen();
    std::cout << "=== managing vpn: " << selected_vpn.name << " ===\n";
    std::cout << "1) add client\n";
    std::cout << "2) revoke client\n";
    std::cout << "3) start/stop service\n";
    std::cout << "4) remove vpn\n";
    std::cout << "5) back\n\n";
    
    int action = get_user_choice("select action", 1, 5);
    
    switch (action) {
        case 1: {
            ClientConfig client_config = collect_client_info();
            if (add_client_use_case_->execute(selected_vpn.name, client_config)) {
                std::cout << "client '" << client_config.name << "' added successfully\n";
                std::cout << "configuration file: ~/" << selected_vpn.name << "-" << client_config.name << ".ovpn\n";
            } else {
                std::cout << "failed to add client '" << client_config.name << "'\n";
            }
            break;
        }
        case 2: {
            std::string client_name = get_user_input("client name to revoke: ");
            if (get_user_confirmation("confirm revocation of '" + client_name + "'")) {
                if (revoke_client_use_case_->execute(selected_vpn.name, client_name)) {
                    std::cout << "client '" << client_name << "' revoked successfully\n";
                } else {
                    std::cout << "failed to revoke client '" << client_name << "'\n";
                }
            }
            break;
        }
        case 3: {
            bool is_active = manage_service_use_case_->get_status(selected_vpn.name);
            std::cout << "service status: " << (is_active ? "active" : "inactive") << "\n";
            
            if (is_active) {
                if (get_user_confirmation("stop service")) {
                    manage_service_use_case_->stop_vpn(selected_vpn.name);
                    std::cout << "service stopped\n";
                }
            } else {
                if (get_user_confirmation("start service")) {
                    manage_service_use_case_->start_vpn(selected_vpn.name);
                    std::cout << "service started\n";
                }
            }
            break;
        }
        case 4: {
            if (get_user_confirmation("remove vpn '" + selected_vpn.name + "' permanently")) {
                if (remove_vpn_use_case_->execute(selected_vpn.name)) {
                    std::cout << "vpn '" << selected_vpn.name << "' removed successfully\n";
                } else {
                    std::cout << "failed to remove vpn '" << selected_vpn.name << "'\n";
                }
            }
            break;
        }
    }
}

void CLIController::handle_list_vpns() {
    clear_screen();
    std::cout << "=== vpn configurations ===\n\n";
    
    auto vpns = list_vpns_use_case_->execute();
    if (vpns.empty()) {
        std::cout << "no vpn configurations found\n";
        return;
    }
    
    for (const auto& vpn : vpns) {
        bool is_active = manage_service_use_case_->get_status(vpn.name);
        std::cout << "name: " << vpn.name << "\n";
        std::cout << "status: " << (is_active ? "active" : "inactive") << "\n";
        std::cout << "protocol: " << (vpn.protocol == Protocol::UDP ? "udp" : "tcp") << "\n";
        std::cout << "port: " << vpn.port << "\n";
        std::cout << "network: " << vpn.network.subnet_address << "/24\n";
        std::cout << "\n";
    }
}

void CLIController::handle_service_status() {
    clear_screen();
    std::cout << "=== service status ===\n\n";
    
    auto vpns = list_vpns_use_case_->execute();
    if (vpns.empty()) {
        std::cout << "no vpn services found\n";
        return;
    }
    
    for (const auto& vpn : vpns) {
        bool is_active = manage_service_use_case_->get_status(vpn.name);
        std::cout << vpn.name << ": " << (is_active ? "active" : "inactive") << "\n";
    }
}

VPNConfig CLIController::collect_vpn_configuration() {
    VPNConfig config;
    
    config.name = collect_vpn_name();
    config.network.ipv4_address = collect_host_ip();
    config.protocol = collect_protocol();
    config.port = collect_port();
    
    auto subnet_info = collect_subnet_address();
    config.network.subnet_address = subnet_info.first;
    config.network.subnet_number = subnet_info.second;
    
    config.dns_provider = collect_dns_provider();
    config.crypto_algorithm = CryptoAlgorithm::SECP256K1;
    config.network.ipv6_enabled = false;
    
    return config;
}

std::string CLIController::collect_vpn_name() {
    std::string name;
    do {
        name = get_user_input("vpn name: ");
        if (name.empty() && std::cin.eof()) {
            exit(0);
        }
        name = sanitize_name(name);
        if (name.empty()) {
            std::cout << "invalid name\n";
        }
    } while (name.empty());
    
    return name;
}

std::string CLIController::collect_client_name() {
    std::string name;
    do {
        name = get_user_input("client name [client]: ");
        if (name.empty()) name = "client";
        name = sanitize_name(name);
        if (name.empty()) {
            std::cout << "invalid name\n";
        }
    } while (name.empty());
    
    return name;
}

ClientConfig CLIController::collect_client_info() {
    ClientConfig client_config;
    client_config.name = collect_client_name();
    client_config.is_revoked = false;
    
    std::cout << "\nroute-nopull prevents the client from pulling routes from the server.\n";
    std::cout << "this means the client won't redirect all traffic through the vpn.\n";
    std::cout << "by default, route-nopull is enabled for security.\n";
    client_config.use_route_nopull = !get_user_confirmation("disable route-nopull (redirect all traffic through vpn)");
    
    return client_config;
}

std::string CLIController::collect_host_ip() {
    std::cout << "host ip configuration:\n";
    std::cout << "select the ip address that will be used as the vpn server host:\n";
    
    auto addresses = std::dynamic_pointer_cast<LinuxNetworkService>(network_service_)->get_available_ip_addresses();
    
    if (addresses.empty()) {
        std::cout << "no network interfaces found, using auto-detect\n";
        return "0.0.0.0";
    }
    
    for (size_t i = 0; i < addresses.size(); ++i) {
        std::cout << i + 1 << ") " << addresses[i] << "\n";
    }
    
    int choice = get_user_choice("host ip [1]", 1, static_cast<int>(addresses.size()));
    std::string selected = addresses[choice - 1];
    
    size_t space_pos = selected.find(' ');
    if (space_pos != std::string::npos) {
        selected = selected.substr(0, space_pos);
    }
    
    if (selected == "0.0.0.0") {
        auto network_config = std::dynamic_pointer_cast<LinuxNetworkService>(network_service_)->detect_network_configuration();
        if (!network_config.ipv4_address.empty()) {
            selected = network_config.ipv4_address;
        }
    } else if (selected == "::/0") {
        auto network_config = std::dynamic_pointer_cast<LinuxNetworkService>(network_service_)->detect_network_configuration();
        if (!network_config.ipv6_address.empty()) {
            selected = network_config.ipv6_address;
        }
    }
    
    return selected;
}

Protocol CLIController::collect_protocol() {
    std::cout << "protocol:\n";
    std::cout << "1) udp (recommended)\n";
    std::cout << "2) tcp\n";
    
    int choice = get_user_choice("protocol [1]", 1, 2);
    return (choice == 2) ? Protocol::TCP : Protocol::UDP;
}

uint16_t CLIController::collect_port() {
    std::string input = get_user_input("port [1194]: ");
    if (input.empty()) return 1194;
    
    try {
        int port = std::stoi(input);
        if (port > 0 && port <= 65535) {
            return static_cast<uint16_t>(port);
        }
    } catch (const std::exception&) {
    }
    
    std::cout << "invalid port, using default 1194\n";
    return 1194;
}

std::pair<std::string, uint16_t> CLIController::collect_subnet_address() {
    std::cout << "intranet configuration:\n";
    std::cout << "enter subnet address (example: 10.8.5.0, 192.168.100.0)\n";
    
    std::string input = get_user_input("subnet address [10.8.8.0]: ");
    if (input.empty()) {
        return std::make_pair("10.8.8.0", 8);
    }
    
    std::regex subnet_pattern(R"(^(\d+)\.(\d+)\.(\d+)\.0$)");
    std::smatch matches;
    
    if (std::regex_match(input, matches, subnet_pattern)) {
        try {
            int first = std::stoi(matches[1].str());
            int second = std::stoi(matches[2].str());
            int third = std::stoi(matches[3].str());
            
            if (first >= 0 && first <= 255 && 
                second >= 0 && second <= 255 && 
                third >= 0 && third <= 255) {
                
                return std::make_pair(input, static_cast<uint16_t>(third));
            }
        } catch (const std::exception&) {
        }
    }
    
    std::cout << "invalid subnet format, using default 10.8.8.0\n";
    return std::make_pair("10.8.8.0", 8);
}

DNSProvider CLIController::collect_dns_provider() {
    std::cout << "dns provider:\n";
    std::cout << "1) system resolvers\n";
    std::cout << "2) google\n";
    std::cout << "3) cloudflare\n";
    std::cout << "4) opendns\n";
    std::cout << "5) quad9\n";
    std::cout << "6) adguard\n";
    
    int choice = get_user_choice("dns provider [1]", 1, 6);
    return static_cast<DNSProvider>(choice);
}

std::string CLIController::sanitize_name(const std::string& name) {
    std::regex valid_chars("[^a-zA-Z0-9_-]");
    return std::regex_replace(name, valid_chars, "_");
}

void CLIController::clear_screen() {
    std::cout << "\033[2J\033[H";
}

void CLIController::wait_for_enter() {
    std::cout << "\npress enter to continue...";
    std::string dummy;
    std::getline(std::cin, dummy);
}

std::string CLIController::get_user_input(const std::string& prompt) {
    std::cout << prompt;
    std::string input;
    if (!std::getline(std::cin, input)) {
        return "";
    }
    return input;
}

int CLIController::get_user_choice(const std::string& prompt, int min_value, int max_value) {
    int choice = 0;
    std::string input;
    
    do {
        std::cout << prompt << " [" << min_value << "-" << max_value << "]: ";
        std::getline(std::cin, input);
        
        if (input.empty()) {
            choice = min_value;
            break;
        }
        
        try {
            choice = std::stoi(input);
        } catch (const std::exception&) {
            choice = 0;
        }
        
        if (choice < min_value || choice > max_value) {
            std::cout << "invalid choice\n";
        }
    } while (choice < min_value || choice > max_value);
    
    return choice;
}

bool CLIController::get_user_confirmation(const std::string& prompt) {
    std::cout << prompt << " [y/N]: ";
    std::string response;
    std::getline(std::cin, response);
    
    return !response.empty() && (response[0] == 'y' || response[0] == 'Y');
}

}
