#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace openvpn_manager {

enum class Protocol {
    UDP,
    TCP
};

enum class DNSProvider {
    SYSTEM = 1,
    GOOGLE = 2,
    CLOUDFLARE = 3,
    OPENDNS = 4,
    QUAD9 = 5,
    ADGUARD = 6
};

enum class CryptoAlgorithm {
    RSA_4096,
    EC_SECP384R1
};

struct NetworkConfig {
    std::string ipv4_address;
    std::string ipv6_address;
    std::string public_ip;
    std::string subnet_address;
    uint16_t subnet_number;
    bool ipv6_enabled;
};

struct VPNConfig {
    std::string name;
    Protocol protocol;
    uint16_t port;
    DNSProvider dns_provider;
    NetworkConfig network;
    CryptoAlgorithm crypto_algorithm;
    std::string server_dir;
    std::string easyrsa_dir;
};

struct ClientConfig {
    std::string name;
    std::string vpn_name;
    std::string certificate_path;
    std::string private_key_path;
    bool is_revoked;
    bool use_route_nopull;
};

using VPNConfigPtr = std::shared_ptr<VPNConfig>;
using ClientConfigPtr = std::shared_ptr<ClientConfig>;

}
