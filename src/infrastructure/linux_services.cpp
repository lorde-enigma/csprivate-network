#include "infrastructure/linux_services.h"
#include "infrastructure/linux_implementations.h"
#include "infrastructure/certificate_service.h"
#include "infrastructure/logger.h"
#include "infrastructure/file_system_repository.h"
#include "presentation/cli_controller.h"
#include <sstream>

namespace openvpn_manager {

LinuxNetworkService::LinuxNetworkService(
    std::shared_ptr<ProcessExecutor> process_executor,
    std::shared_ptr<FileSystem> file_system,
    std::shared_ptr<Logger> logger
) : process_executor_(process_executor), file_system_(file_system), logger_(logger) {}

NetworkConfig LinuxNetworkService::detect_network_configuration() {
    NetworkConfig config;
    
    auto result = process_executor_->execute("ip -4 addr | grep inet | grep -vE '127(\\.[0-9]{1,3}){3}' | head -1 | awk '{print $2}' | cut -d'/' -f1");
    if (result.exit_code == 0) {
        config.ipv4_address = result.stdout_output;
        config.ipv4_address.erase(config.ipv4_address.find_last_not_of("\n\r") + 1);
    }
    
    result = process_executor_->execute("ip -6 addr | grep 'inet6 [23]' | head -1 | awk '{print $2}' | cut -d'/' -f1");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        config.ipv6_address = result.stdout_output;
        config.ipv6_address.erase(config.ipv6_address.find_last_not_of("\n\r") + 1);
        config.ipv6_enabled = true;
    }
    
    return config;
}

std::vector<std::string> LinuxNetworkService::get_available_ip_addresses() {
    std::vector<std::string> addresses;
    
    auto result = process_executor_->execute("ip -4 addr show | grep inet | grep -v '127\\.' | awk '{print $2}' | cut -d'/' -f1");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        std::istringstream stream(result.stdout_output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line != "127.0.0.1") {
                std::string ip = line;
                ip.erase(ip.find_last_not_of("\n\r") + 1);
                
                bool is_private = false;
                if (ip.substr(0, 3) == "10." ||
                    (ip.substr(0, 4) == "172." && ip.length() >= 7)) {
                    size_t second_dot = ip.find('.', 4);
                    if (second_dot != std::string::npos) {
                        try {
                            int second_octet = std::stoi(ip.substr(4, second_dot - 4));
                            is_private = (second_octet >= 16 && second_octet <= 31);
                        } catch (const std::exception&) {
                            is_private = false;
                        }
                    }
                } else if (ip.substr(0, 8) == "192.168." ||
                           ip.substr(0, 8) == "169.254.") {
                    is_private = true;
                } else {
                    is_private = (ip.substr(0, 3) == "10.");
                }
                
                addresses.push_back(ip + (is_private ? " (IPv4 private)" : " (IPv4 public)"));
            }
        }
    }
    
    result = process_executor_->execute("ip -6 addr show | grep 'inet6 [23]' | grep -v 'fe80:' | awk '{print $2}' | cut -d'/' -f1");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        std::istringstream stream(result.stdout_output);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line != "::1") {
                std::string ip = line;
                ip.erase(ip.find_last_not_of("\n\r") + 1);
                
                bool is_private = false;
                if (ip.length() >= 4) {
                    std::string prefix = ip.substr(0, 4);
                    if (prefix.substr(0, 2) == "fc" || prefix.substr(0, 2) == "fd" || 
                        prefix.substr(0, 3) == "fec") {
                        is_private = true;
                    }
                }
                
                addresses.push_back(ip + (is_private ? " (IPv6 private)" : " (IPv6 public)"));
            }
        }
    }
    
    addresses.insert(addresses.begin(), "::/0 (IPv6 auto-detect)");
    addresses.insert(addresses.begin(), "0.0.0.0 (IPv4 auto-detect)");
    
    return addresses;
}

uint16_t LinuxNetworkService::get_next_available_subnet() {
    uint16_t subnet = 0;
    auto result = process_executor_->execute("grep -h '^server ' /etc/openvpn/server-*/server.conf 2>/dev/null | awk '{print $2}' | cut -d'.' -f3 | sort -n | tail -1");
    
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        try {
            subnet = static_cast<uint16_t>(std::stoi(result.stdout_output) + 1);
        } catch (const std::exception&) {
            subnet = 0;
        }
    }
    
    return subnet;
}

uint16_t LinuxNetworkService::get_next_available_port() {
    uint16_t port = 1194;
    auto result = process_executor_->execute("grep -h '^port ' /etc/openvpn/server-*/server.conf 2>/dev/null | awk '{print $2}' | sort -n | tail -1");
    
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        try {
            port = static_cast<uint16_t>(std::stoi(result.stdout_output) + 1);
        } catch (const std::exception&) {
            port = 1194;
        }
    }
    
    return port;
}

bool LinuxNetworkService::enable_ip_forwarding() {
    auto result = process_executor_->execute("echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf");
    if (result.exit_code != 0) return false;
    
    result = process_executor_->execute("echo 1 > /proc/sys/net/ipv4/ip_forward");
    if (result.exit_code != 0) return false;
    
    result = process_executor_->execute("echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/99-openvpn-forward.conf");
    if (result.exit_code != 0) return false;
    
    result = process_executor_->execute("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding");
    if (result.exit_code != 0) return false;
    
    result = process_executor_->execute("sysctl -p /etc/sysctl.d/99-openvpn-forward.conf");
    return result.exit_code == 0;
}

bool LinuxNetworkService::configure_firewall(const VPNConfig& config) {
    std::string subnet = config.network.subnet_address + "/24";
    std::string protocol = (config.protocol == Protocol::UDP) ? "udp" : "tcp";
    
    std::string public_ip = detect_public_ip();
    if (public_ip.empty()) {
        logger_->error("failed to detect public IP address for NAT");
        return false;
    }
    
    auto result = process_executor_->execute("systemctl is-active --quiet firewalld");
    if (result.exit_code == 0) {
        return configure_firewalld_with_ip(config, subnet, protocol, public_ip);
    } else {
        return configure_iptables_with_ip(config, subnet, protocol, public_ip);
    }
}

bool LinuxNetworkService::remove_firewall_rules(const VPNConfig& config) {
    std::string subnet = config.network.subnet_address + "/24";
    std::string protocol = (config.protocol == Protocol::UDP) ? "udp" : "tcp";
    
    auto result = process_executor_->execute("systemctl is-active --quiet firewalld");
    if (result.exit_code == 0) {
        return remove_firewalld_rules(config, subnet, protocol);
    } else {
        return remove_iptables_rules(config);
    }
}

bool LinuxNetworkService::configure_firewalld(const VPNConfig& config, const std::string& subnet, const std::string& protocol) {
    std::vector<std::string> commands = {
        "firewall-cmd --add-port=" + std::to_string(config.port) + "/" + protocol,
        "firewall-cmd --zone=trusted --add-source=" + subnet,
        "firewall-cmd --permanent --add-port=" + std::to_string(config.port) + "/" + protocol,
        "firewall-cmd --permanent --zone=trusted --add-source=" + subnet,
        "firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s " + subnet + " ! -d " + subnet + " -j SNAT --to " + config.network.ipv4_address,
        "firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s " + subnet + " ! -d " + subnet + " -j SNAT --to " + config.network.ipv4_address
    };
    
    for (const auto& cmd : commands) {
        auto result = process_executor_->execute(cmd);
        if (result.exit_code != 0) {
            logger_->error("firewalld command failed: " + cmd);
            return false;
        }
    }
    
    return true;
}

bool LinuxNetworkService::configure_iptables(const VPNConfig& config, const std::string& subnet, const std::string& protocol) {
    auto file_system = std::make_shared<LinuxFileSystem>();
    std::string service_content = R"([Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables -t nat -A POSTROUTING -s )" + subnet + " ! -d " + subnet + " -j SNAT --to " + config.network.ipv4_address + R"(
ExecStart=/usr/sbin/iptables -I INPUT -p )" + protocol + " --dport " + std::to_string(config.port) + R"( -j ACCEPT
ExecStart=/usr/sbin/iptables -I FORWARD -s )" + subnet + R"( -j ACCEPT
ExecStart=/usr/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/usr/sbin/iptables -t nat -D POSTROUTING -s )" + subnet + " ! -d " + subnet + " -j SNAT --to " + config.network.ipv4_address + R"(
ExecStop=/usr/sbin/iptables -D INPUT -p )" + protocol + " --dport " + std::to_string(config.port) + R"( -j ACCEPT
ExecStop=/usr/sbin/iptables -D FORWARD -s )" + subnet + R"( -j ACCEPT
ExecStop=/usr/sbin/iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
)";
    
    std::string service_file = "/etc/systemd/system/openvpn-iptables-" + config.name + ".service";
    
    if (!file_system->write_file(service_file, service_content)) {
        logger_->error("failed to create iptables service file: " + service_file);
        return false;
    }
    
    auto result = process_executor_->execute("systemctl enable --now openvpn-iptables-" + config.name + ".service");
    return result.exit_code == 0;
}

bool LinuxNetworkService::remove_firewalld_rules(const VPNConfig& config, const std::string& subnet, const std::string& protocol) {
    std::vector<std::string> commands = {
        "firewall-cmd --remove-port=" + std::to_string(config.port) + "/" + protocol,
        "firewall-cmd --zone=trusted --remove-source=" + subnet,
        "firewall-cmd --permanent --remove-port=" + std::to_string(config.port) + "/" + protocol,
        "firewall-cmd --permanent --zone=trusted --remove-source=" + subnet
    };
    
    for (const auto& cmd : commands) {
        process_executor_->execute(cmd);
    }
    
    return true;
}

bool LinuxNetworkService::remove_iptables_rules(const VPNConfig& config) {
    auto result = process_executor_->execute("systemctl disable --now openvpn-iptables-" + config.name + ".service");
    process_executor_->execute("rm -f /etc/systemd/system/openvpn-iptables-" + config.name + ".service");
    return true;
}

LinuxSystemService::LinuxSystemService(
    std::shared_ptr<ProcessExecutor> process_executor,
    std::shared_ptr<Logger> logger
) : process_executor_(process_executor), logger_(logger) {}

bool LinuxSystemService::install_dependencies() {
    auto detector = std::make_shared<LinuxSystemDetector>();
    auto os_type = detector->detect_os();
    
    std::string install_cmd;
    switch (os_type) {
        case SystemDetector::OSType::UBUNTU:
        case SystemDetector::OSType::DEBIAN:
            install_cmd = "apt-get update && apt-get install -y openvpn openssl ca-certificates";
            break;
        case SystemDetector::OSType::CENTOS:
            install_cmd = "dnf install -y epel-release && dnf install -y openvpn openssl ca-certificates";
            break;
        case SystemDetector::OSType::FEDORA:
            install_cmd = "dnf install -y openvpn openssl ca-certificates";
            break;
        default:
            logger_->error("unsupported operating system");
            return false;
    }
    
    auto result = process_executor_->execute(install_cmd);
    return result.exit_code == 0;
}

bool LinuxSystemService::create_systemd_service(const std::string&) {
    return true;
}

bool LinuxSystemService::start_service(const std::string& vpn_name) {
    auto result = process_executor_->execute("systemctl start openvpn-server@" + vpn_name + ".service");
    return result.exit_code == 0;
}

bool LinuxSystemService::stop_service(const std::string& vpn_name) {
    auto result = process_executor_->execute("systemctl stop openvpn-server@" + vpn_name + ".service");
    return result.exit_code == 0;
}

bool LinuxSystemService::enable_service(const std::string& vpn_name) {
    auto result = process_executor_->execute("systemctl enable openvpn-server@" + vpn_name + ".service");
    return result.exit_code == 0;
}

bool LinuxSystemService::disable_service(const std::string& vpn_name) {
    auto result = process_executor_->execute("systemctl disable openvpn-server@" + vpn_name + ".service");
    return result.exit_code == 0;
}

bool LinuxSystemService::is_service_active(const std::string& vpn_name) {
    auto result = process_executor_->execute("systemctl is-active --quiet openvpn-server@" + vpn_name + ".service");
    return result.exit_code == 0;
}

bool LinuxSystemService::remove_service(const std::string& vpn_name) {
    stop_service(vpn_name);
    disable_service(vpn_name);
    
    auto result = process_executor_->execute("rm -f /etc/systemd/system/openvpn-server@" + vpn_name + ".service.d/disable-limitnproc.conf");
    process_executor_->execute("systemctl daemon-reload");
    
    return true;
}

LinuxConfigurationService::LinuxConfigurationService(
    std::shared_ptr<FileSystem> file_system,
    std::shared_ptr<ProcessExecutor> process_executor,
    std::shared_ptr<Logger> logger
) : file_system_(file_system), process_executor_(process_executor), logger_(logger) {}

bool LinuxConfigurationService::generate_server_config(const VPNConfig& config) {
    std::string config_content = generate_server_config_content(config);
    std::string config_file = config.server_dir + "/server.conf";
    std::string systemd_config_content = generate_systemd_server_config_content(config);
    std::string systemd_config_file = "/etc/openvpn/server/" + config.name + ".conf";
    
    if (!file_system_->write_file(config_file, config_content)) {
        logger_->error("failed to write server configuration: " + config_file);
        return false;
    }
    
    if (!file_system_->directory_exists("/etc/openvpn/server") && !file_system_->create_directory("/etc/openvpn/server")) {
        logger_->error("failed to create systemd config directory");
        return false;
    }
    
    if (!file_system_->write_file(systemd_config_file, systemd_config_content)) {
        logger_->error("failed to write systemd server configuration: " + systemd_config_file);
        return false;
    }
    
    logger_->info("server_dir value: '" + config.server_dir + "'");
    if (!fix_certificate_permissions(config.server_dir)) {
        logger_->error("failed to fix certificate permissions for: " + config.name);
        return false;
    }
    
    logger_->info("generated server configuration for: " + config.name);
    return true;
}

bool LinuxConfigurationService::generate_client_config(const std::string& vpn_name, const std::string& client_name) {
    std::string template_file = "/etc/openvpn/server-" + vpn_name + "/client-common.txt";
    std::string server_dir = "/etc/openvpn/server-" + vpn_name;
    std::string tc_key_file = server_dir + "/tc.key";
    
    std::string template_content = file_system_->read_file(template_file);
    std::string ca_cert = file_system_->read_file(server_dir + "/ca.crt");
    std::string client_cert = file_system_->read_file(server_dir + "/" + client_name + ".crt");
    std::string client_key = file_system_->read_file(server_dir + "/" + client_name + ".key");
    std::string tc_key = file_system_->read_file(tc_key_file);
    
    std::string client_config = template_content + "\n<ca>\n" + ca_cert + "</ca>\n";
    client_config += "<cert>\n" + extract_certificate_content(client_cert) + "</cert>\n";
    client_config += "<key>\n" + client_key + "</key>\n";
    client_config += "<tls-crypt>\n" + extract_tls_crypt_content(tc_key) + "</tls-crypt>\n";
    
    std::string output_file = "/root/" + vpn_name + "-" + client_name + ".ovpn";
    
    if (!file_system_->write_file(output_file, client_config)) {
        logger_->error("failed to write client configuration: " + output_file);
        return false;
    }
    
    logger_->info("generated client configuration: " + output_file);
    return true;
}

bool LinuxConfigurationService::generate_client_template(const VPNConfig& config) {
    std::string template_content = generate_client_template_content(config);
    std::string template_file = config.server_dir + "/client-common.txt";
    
    if (!file_system_->write_file(template_file, template_content)) {
        logger_->error("failed to write client template: " + template_file);
        return false;
    }
    
    logger_->info("generated client template for: " + config.name);
    return true;
}

std::string LinuxConfigurationService::get_client_config_path(const std::string& vpn_name, const std::string& client_name) {
    return "/root/" + vpn_name + "-" + client_name + ".ovpn";
}

bool LinuxConfigurationService::fix_certificate_permissions(const std::string& server_dir) {
    logger_->info("fixing permissions for directory: '" + server_dir + "'");
    
    if (server_dir.empty()) {
        logger_->error("server_dir is empty, cannot fix permissions");
        return false;
    }
    
    auto check_command_result = [this](const ProcessExecutor::ExecutionResult& result, const std::string& operation) {
        if (result.exit_code != 0) {
            logger_->error("failed " + operation + ": " + result.stderr_output);
            return false;
        }
        return true;
    };
    
    auto result = process_executor_->execute("getent group openvpn >/dev/null 2>&1");
    if (result.exit_code != 0) {
        logger_->info("creating openvpn group");
        result = process_executor_->execute("groupadd openvpn");
        if (!check_command_result(result, "creating group openvpn")) return false;
    }
    
    std::vector<std::string> users = {"nobody", "openvpn"};
    for (const auto& user : users) {
        result = process_executor_->execute("id " + user + " >/dev/null 2>&1");
        if (result.exit_code == 0) {
            result = process_executor_->execute("groups " + user + " | grep -q openvpn");
            if (result.exit_code != 0) {
                logger_->info("adding user " + user + " to openvpn group");
                result = process_executor_->execute("usermod -a -G openvpn " + user);
                if (!check_command_result(result, "adding user " + user + " to group")) return false;
            }
        }
    }
    
    std::string ipp_file = server_dir + "/ipp.txt";
    result = process_executor_->execute("test -f " + ipp_file);
    if (result.exit_code != 0) {
        logger_->info("creating ipp.txt file");
        result = process_executor_->execute("touch " + ipp_file);
        if (!check_command_result(result, "creating ipp.txt")) return false;
    }
    
    result = process_executor_->execute("stat -c '%G' " + server_dir + " | grep -q openvpn");
    if (result.exit_code != 0) {
        logger_->info("setting directory group ownership");
        result = process_executor_->execute("chgrp -R openvpn " + server_dir);
        if (!check_command_result(result, "setting directory group")) return false;
    }
    
    std::vector<std::pair<std::string, std::string>> file_permissions = {
        {server_dir, "770"},
        {server_dir + "/ca.crt", "640"},
        {server_dir + "/server.crt", "640"},
        {server_dir + "/server.key", "640"},
        {server_dir + "/dh.pem", "640"},
        {server_dir + "/tc.key", "640"},
        {server_dir + "/crl.pem", "640"},
        {server_dir + "/ipp.txt", "660"}
    };
    
    for (const auto& [path, perm] : file_permissions) {
        result = process_executor_->execute("test -e " + path);
        if (result.exit_code == 0) {
            result = process_executor_->execute("stat -c '%a' " + path + " | grep -q " + perm);
            if (result.exit_code != 0) {
                logger_->info("setting permissions " + perm + " for " + path);
                result = process_executor_->execute("chmod " + perm + " " + path);
                if (!check_command_result(result, "setting permissions for " + path)) return false;
            }
        }
    }
    
    result = process_executor_->execute("chmod -R g+r " + server_dir);
    if (!check_command_result(result, "setting group read permissions")) return false;
    
    result = process_executor_->execute("chmod g+x " + server_dir);
    if (!check_command_result(result, "setting directory execute permissions")) return false;
    
    logger_->info("all permissions verified and corrected for: " + server_dir);
    return true;
}

std::string LinuxConfigurationService::generate_server_config_content(const VPNConfig& config) {
    std::string protocol_str = (config.protocol == Protocol::UDP) ? "udp" : "tcp";
    std::string server_name = "server-" + config.name;
    std::string subnet = config.network.subnet_address;
    
    std::string content = "local " + config.network.ipv4_address + "\n";
    content += "port " + std::to_string(config.port) + "\n";
    content += "proto " + protocol_str + "\n";
    content += "dev tun-" + config.name + "\n";
    content += "ca easy-rsa/pki/ca.crt\n";
    content += "cert easy-rsa/pki/issued/" + server_name + ".crt\n";
    content += "key easy-rsa/pki/private/" + server_name + ".key\n";
    content += "dh easy-rsa/pki/dh.pem\n";
    content += "auth SHA384\n";
    content += "cipher AES-256-GCM\n";
    content += "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC\n";
    content += "tls-crypt tc.key\n";
    content += "tls-version-min 1.2\n";
    content += "topology subnet\n";
    content += "server " + subnet + " 255.255.255.0\n";
    
    if (config.network.ipv6_enabled) {
        auto last_dot = config.network.subnet_address.find_last_of('.');
        auto third_dot = config.network.subnet_address.find_last_of('.', last_dot - 1);
        std::string third_octet = "8";
        if (third_dot != std::string::npos && last_dot != std::string::npos) {
            third_octet = config.network.subnet_address.substr(third_dot + 1, last_dot - third_dot - 1);
        }
        content += "server-ipv6 fddd:1194:" + third_octet + "::/64\n";
        content += "push \"redirect-gateway def1 ipv6 bypass-dhcp\"\n";
        content += "push \"route-ipv6 2000::/3\"\n";
        content += "push \"dhcp-option DNS6 2001:4860:4860::8888\"\n";
        content += "push \"dhcp-option DNS6 2001:4860:4860::8844\"\n";
    } else {
        content += "push \"redirect-gateway def1 bypass-dhcp\"\n";
    }
    
    content += "ifconfig-pool-persist ipp.txt\n";
    content += add_dns_configuration(config.dns_provider);
    content += "push \"block-outside-dns\"\n";
    content += "keepalive 10 120\n";
    content += "user nobody\n";
    content += "group nobody\n";
    content += "persist-key\n";
    content += "persist-tun\n";
    content += "verb 3\n";
    content += "crl-verify easy-rsa/pki/crl.pem\n";
    content += "management localhost " + std::to_string(config.port + 1000) + "\n";
    
    if (config.protocol == Protocol::UDP) {
        content += "explicit-exit-notify\n";
    }
    
    return content;
}

std::string LinuxConfigurationService::generate_systemd_server_config_content(const VPNConfig& config) {
    std::string protocol_str = (config.protocol == Protocol::UDP) ? "udp" : "tcp";
    std::string server_name = "server-" + config.name;
    std::string subnet = config.network.subnet_address;
    std::string server_dir = "/etc/openvpn/server-" + config.name;
    
    std::string content = "local " + config.network.ipv4_address + "\n";
    content += "port " + std::to_string(config.port) + "\n";
    content += "proto " + protocol_str + "\n";
    content += "dev tun-" + config.name + "\n";
    content += "ca " + server_dir + "/ca.crt\n";
    content += "cert " + server_dir + "/server.crt\n";
    content += "key " + server_dir + "/server.key\n";
    content += "dh " + server_dir + "/dh.pem\n";
    content += "auth SHA384\n";
    content += "cipher AES-256-GCM\n";
    content += "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC\n";
    content += "tls-crypt " + server_dir + "/tc.key\n";
    content += "tls-version-min 1.2\n";
    content += "topology subnet\n";
    content += "server " + subnet + " 255.255.255.0\n";
    
    if (config.network.ipv6_enabled) {
        auto last_dot = config.network.subnet_address.find_last_of('.');
        auto third_dot = config.network.subnet_address.find_last_of('.', last_dot - 1);
        std::string third_octet = "8";
        if (third_dot != std::string::npos && last_dot != std::string::npos) {
            third_octet = config.network.subnet_address.substr(third_dot + 1, last_dot - third_dot - 1);
        }
        content += "server-ipv6 fddd:1194:" + third_octet + "::/64\n";
        content += "push \"redirect-gateway def1 ipv6 bypass-dhcp\"\n";
        content += "push \"route-ipv6 2000::/3\"\n";
        content += "push \"dhcp-option DNS6 2001:4860:4860::8888\"\n";
        content += "push \"dhcp-option DNS6 2001:4860:4860::8844\"\n";
    } else {
        content += "push \"redirect-gateway def1 bypass-dhcp\"\n";
    }
    
    content += "ifconfig-pool-persist ipp.txt\n";
    content += add_dns_configuration(config.dns_provider);
    content += "push \"block-outside-dns\"\n";
    content += "keepalive 10 120\n";
    content += "user nobody\n";
    content += "group openvpn\n";
    content += "persist-key\n";
    content += "persist-tun\n";
    content += "verb 3\n";
    content += "crl-verify " + server_dir + "/crl.pem\n";
    content += "management localhost " + std::to_string(config.port + 1000) + "\n";
    
    if (config.protocol == Protocol::UDP) {
        content += "explicit-exit-notify\n";
    }
    
    return content;
}

std::string LinuxConfigurationService::generate_client_template_content(const VPNConfig& config) {
    std::string protocol_str = (config.protocol == Protocol::UDP) ? "udp" : "tcp";
    std::string remote_ip = config.network.public_ip.empty() ? config.network.ipv4_address : config.network.public_ip;
    
    std::string content = "client\n";
    content += "dev tun\n";
    content += "proto " + protocol_str + "\n";
    content += "remote " + remote_ip + " " + std::to_string(config.port) + "\n";
    content += "resolv-retry infinite\n";
    content += "nobind\n";
    content += "persist-key\n";
    content += "persist-tun\n";
    content += "remote-cert-tls server\n";
    content += "auth SHA384\n";
    content += "cipher AES-256-GCM\n";
    content += "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC\n";
    content += "tls-version-min 1.2\n";
    content += "ignore-unknown-option block-outside-dns\n";
    content += "verb 3\n";
    
    return content;
}

std::string LinuxConfigurationService::add_dns_configuration(DNSProvider provider) {
    std::string dns_config;
    
    switch (provider) {
        case DNSProvider::GOOGLE:
            dns_config = "push \"dhcp-option DNS 8.8.8.8\"\npush \"dhcp-option DNS 8.8.4.4\"\n";
            dns_config += "push \"dhcp-option DNS6 2001:4860:4860::8888\"\npush \"dhcp-option DNS6 2001:4860:4860::8844\"\n";
            break;
        case DNSProvider::CLOUDFLARE:
            dns_config = "push \"dhcp-option DNS 1.1.1.1\"\npush \"dhcp-option DNS 1.0.0.1\"\n";
            dns_config += "push \"dhcp-option DNS6 2606:4700:4700::1111\"\npush \"dhcp-option DNS6 2606:4700:4700::1001\"\n";
            break;
        case DNSProvider::OPENDNS:
            dns_config = "push \"dhcp-option DNS 208.67.222.222\"\npush \"dhcp-option DNS 208.67.220.220\"\n";
            dns_config += "push \"dhcp-option DNS6 2620:119:35::35\"\npush \"dhcp-option DNS6 2620:119:53::53\"\n";
            break;
        case DNSProvider::QUAD9:
            dns_config = "push \"dhcp-option DNS 9.9.9.9\"\npush \"dhcp-option DNS 149.112.112.112\"\n";
            dns_config += "push \"dhcp-option DNS6 2620:fe::fe\"\npush \"dhcp-option DNS6 2620:fe::9\"\n";
            break;
        case DNSProvider::ADGUARD:
            dns_config = "push \"dhcp-option DNS 94.140.14.14\"\npush \"dhcp-option DNS 94.140.15.15\"\n";
            dns_config += "push \"dhcp-option DNS6 2a10:50c0::ad1:ff\"\npush \"dhcp-option DNS6 2a10:50c0::ad2:ff\"\n";
            break;
        case DNSProvider::SYSTEM:
        default:
            dns_config = "push \"dhcp-option DNS 8.8.8.8\"\npush \"dhcp-option DNS 8.8.4.4\"\n";
            dns_config += "push \"dhcp-option DNS6 2001:4860:4860::8888\"\npush \"dhcp-option DNS6 2001:4860:4860::8844\"\n";
            break;
    }
    
    return dns_config;
}

std::string LinuxConfigurationService::extract_certificate_content(const std::string& cert_file_content) {
    size_t start = cert_file_content.find("-----BEGIN CERTIFICATE-----");
    if (start != std::string::npos) {
        return cert_file_content.substr(start);
    }
    return cert_file_content;
}

std::string LinuxConfigurationService::extract_tls_crypt_content(const std::string& key_file_content) {
    size_t start = key_file_content.find("-----BEGIN OpenVPN Static key");
    if (start != std::string::npos) {
        return key_file_content.substr(start);
    }
    return key_file_content;
}

std::string LinuxNetworkService::detect_public_ip() {
    auto result = process_executor_->execute("ip route get 8.8.8.8 | grep -oP 'src \\K\\S+'");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        std::string ip = result.stdout_output;
        if (!ip.empty() && ip.back() == '\n') {
            ip.pop_back();
        }
        return ip;
    }
    
    result = process_executor_->execute("hostname -I | awk '{print $1}'");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        std::string ip = result.stdout_output;
        if (!ip.empty() && ip.back() == '\n') {
            ip.pop_back();
        }
        return ip;
    }
    
    return "";
}

std::string LinuxNetworkService::detect_public_ipv6() {
    auto result = process_executor_->execute("ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'src \\K\\S+'");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        std::string ip = result.stdout_output;
        if (!ip.empty() && ip.back() == '\n') {
            ip.pop_back();
        }
        if (ip.substr(0, 4) != "fe80") {
            return ip;
        }
    }
    
    result = process_executor_->execute("ip -6 addr show | grep 'inet6 [23]' | grep -v 'fe80:' | head -1 | awk '{print $2}' | cut -d'/' -f1");
    if (result.exit_code == 0 && !result.stdout_output.empty()) {
        std::string ip = result.stdout_output;
        if (!ip.empty() && ip.back() == '\n') {
            ip.pop_back();
        }
        return ip;
    }
    
    return "";
}

bool LinuxNetworkService::configure_firewalld_with_ip(const VPNConfig& config, const std::string& subnet, const std::string& protocol, const std::string& public_ip) {
    std::vector<std::string> commands = {
        "firewall-cmd --add-port=" + std::to_string(config.port) + "/" + protocol,
        "firewall-cmd --zone=trusted --add-source=" + subnet,
        "firewall-cmd --permanent --add-port=" + std::to_string(config.port) + "/" + protocol,
        "firewall-cmd --permanent --zone=trusted --add-source=" + subnet,
        "firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s " + subnet + " ! -d " + subnet + " -j SNAT --to " + public_ip,
        "firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s " + subnet + " ! -d " + subnet + " -j SNAT --to " + public_ip
    };
    
    if (config.network.ipv6_enabled && !config.network.ipv6_address.empty()) {
        auto last_dot = config.network.subnet_address.find_last_of('.');
        auto third_dot = config.network.subnet_address.find_last_of('.', last_dot - 1);
        std::string third_octet = "8";
        if (third_dot != std::string::npos && last_dot != std::string::npos) {
            third_octet = config.network.subnet_address.substr(third_dot + 1, last_dot - third_dot - 1);
        }
        
        std::string ipv6_subnet = "fddd:1194:" + third_octet + "::/64";
        
        commands.insert(commands.end(), {
            "firewall-cmd --zone=trusted --add-source=" + ipv6_subnet,
            "firewall-cmd --permanent --zone=trusted --add-source=" + ipv6_subnet,
            "firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s " + ipv6_subnet + " ! -d " + ipv6_subnet + " -j MASQUERADE",
            "firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s " + ipv6_subnet + " ! -d " + ipv6_subnet + " -j MASQUERADE"
        });
    }
    
    for (const auto& cmd : commands) {
        auto result = process_executor_->execute(cmd);
        if (result.exit_code != 0) {
            logger_->error("firewalld command failed: " + cmd + " - " + result.stderr_output);
            return false;
        }
    }
    
    return true;
}

bool LinuxNetworkService::configure_iptables_with_ip(const VPNConfig& config, const std::string& subnet, const std::string& protocol, const std::string& public_ip) {
    std::string service_content = R"([Unit]
Description=OpenVPN iptables rules for )" + config.name + R"(
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# IPv4 rules
ExecStart=/usr/sbin/iptables -t nat -A POSTROUTING -s )" + subnet + " ! -d " + subnet + " -j SNAT --to " + public_ip + R"(
ExecStart=/usr/sbin/iptables -I INPUT -p )" + protocol + " --dport " + std::to_string(config.port) + R"( -j ACCEPT
ExecStart=/usr/sbin/iptables -I FORWARD -s )" + subnet + R"( -j ACCEPT
ExecStart=/usr/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/usr/sbin/iptables -t nat -D POSTROUTING -s )" + subnet + " ! -d " + subnet + " -j SNAT --to " + public_ip + R"(
ExecStop=/usr/sbin/iptables -D INPUT -p )" + protocol + " --dport " + std::to_string(config.port) + R"( -j ACCEPT
ExecStop=/usr/sbin/iptables -D FORWARD -s )" + subnet + R"( -j ACCEPT
ExecStop=/usr/sbin/iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT)";

    if (config.network.ipv6_enabled && !config.network.ipv6_address.empty()) {
        auto last_dot = config.network.subnet_address.find_last_of('.');
        auto third_dot = config.network.subnet_address.find_last_of('.', last_dot - 1);
        std::string third_octet = "8";
        if (third_dot != std::string::npos && last_dot != std::string::npos) {
            third_octet = config.network.subnet_address.substr(third_dot + 1, last_dot - third_dot - 1);
        }
        
        std::string ipv6_subnet = "fddd:1194:" + third_octet + "::/64";
        
        service_content += R"(
# IPv6 rules
ExecStart=/usr/sbin/ip6tables -t nat -A POSTROUTING -s )" + ipv6_subnet + " ! -d " + ipv6_subnet + R"( -j MASQUERADE
ExecStart=/usr/sbin/ip6tables -I INPUT -p )" + protocol + " --dport " + std::to_string(config.port) + R"( -j ACCEPT
ExecStart=/usr/sbin/ip6tables -I FORWARD -s )" + ipv6_subnet + R"( -j ACCEPT
ExecStart=/usr/sbin/ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/usr/sbin/ip6tables -t nat -D POSTROUTING -s )" + ipv6_subnet + " ! -d " + ipv6_subnet + R"( -j MASQUERADE
ExecStop=/usr/sbin/ip6tables -D INPUT -p )" + protocol + " --dport " + std::to_string(config.port) + R"( -j ACCEPT
ExecStop=/usr/sbin/ip6tables -D FORWARD -s )" + ipv6_subnet + R"( -j ACCEPT
ExecStop=/usr/sbin/ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT)";
    }
    
    service_content += R"(

[Install]
WantedBy=multi-user.target
)";

    std::string service_file = "/etc/systemd/system/openvpn-iptables-" + config.name + ".service";
    
    if (!file_system_->write_file(service_file, service_content)) {
        logger_->error("failed to create iptables service file: " + service_file);
        return false;
    }
    
    auto result = process_executor_->execute("systemctl enable --now openvpn-iptables-" + config.name + ".service");
    if (result.exit_code != 0) {
        logger_->error("failed to enable iptables service: " + result.stderr_output);
        return false;
    }
    
    return true;
}

}
