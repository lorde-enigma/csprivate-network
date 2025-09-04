#include "infrastructure/linux_implementations.h"
#include "domain/services.h"
#include <memory>
#include <string>

namespace openvpn_manager {

class LinuxNetworkService : public NetworkService {
public:
    LinuxNetworkService(
        std::shared_ptr<ProcessExecutor> process_executor,
        std::shared_ptr<FileSystem> file_system,
        std::shared_ptr<Logger> logger
    );
    
    NetworkConfig detect_network_configuration() override;
    std::vector<std::string> get_available_ip_addresses();
    uint16_t get_next_available_subnet() override;
    uint16_t get_next_available_port() override;
    bool enable_ip_forwarding() override;
    bool configure_firewall(const VPNConfig& config) override;
    bool remove_firewall_rules(const VPNConfig& config) override;

private:
    std::shared_ptr<ProcessExecutor> process_executor_;
    std::shared_ptr<FileSystem> file_system_;
    std::shared_ptr<Logger> logger_;
    
    std::string detect_public_ip();
    std::string detect_public_ipv6();
    bool configure_firewalld(const VPNConfig& config, const std::string& subnet, const std::string& protocol);
    bool configure_iptables(const VPNConfig& config, const std::string& subnet, const std::string& protocol);
    bool configure_firewalld_with_ip(const VPNConfig& config, const std::string& subnet, const std::string& protocol, const std::string& public_ip);
    bool configure_iptables_with_ip(const VPNConfig& config, const std::string& subnet, const std::string& protocol, const std::string& public_ip);
    bool remove_firewalld_rules(const VPNConfig& config, const std::string& subnet, const std::string& protocol);
    bool remove_iptables_rules(const VPNConfig& config);
};

class LinuxSystemService : public SystemService {
public:
    LinuxSystemService(
        std::shared_ptr<ProcessExecutor> process_executor,
        std::shared_ptr<Logger> logger
    );
    
    bool install_dependencies() override;
    bool create_systemd_service(const std::string& vpn_name) override;
    bool start_service(const std::string& vpn_name) override;
    bool stop_service(const std::string& vpn_name) override;
    bool enable_service(const std::string& vpn_name) override;
    bool disable_service(const std::string& vpn_name) override;
    bool is_service_active(const std::string& vpn_name) override;
    bool remove_service(const std::string& vpn_name) override;

private:
    std::shared_ptr<ProcessExecutor> process_executor_;
    std::shared_ptr<Logger> logger_;
};

class LinuxConfigurationService : public ConfigurationService {
public:
    LinuxConfigurationService(
        std::shared_ptr<FileSystem> file_system,
        std::shared_ptr<ProcessExecutor> process_executor,
        std::shared_ptr<Logger> logger
    );
    
    bool generate_server_config(const VPNConfig& config) override;
    bool generate_client_config(const std::string& vpn_name, const ClientConfig& client_config) override;
    bool generate_client_template(const VPNConfig& config) override;
    std::string get_client_config_path(const std::string& vpn_name, const std::string& client_name) override;
    bool fix_certificate_permissions(const std::string& server_dir);

private:
    std::shared_ptr<FileSystem> file_system_;
    std::shared_ptr<ProcessExecutor> process_executor_;
    std::shared_ptr<Logger> logger_;
    
    std::string generate_server_config_content(const VPNConfig& config);
    std::string generate_systemd_server_config_content(const VPNConfig& config);
    std::string generate_client_template_content(const VPNConfig& config);
    std::string add_dns_configuration(DNSProvider provider);
    std::string extract_certificate_content(const std::string& cert_file_content);
    std::string extract_tls_crypt_content(const std::string& key_file_content);
};

}
