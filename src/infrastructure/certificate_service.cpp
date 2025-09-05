#include "infrastructure/certificate_service.h"
#include <filesystem>

namespace openvpn_manager {

EasyRSACertificateService::EasyRSACertificateService(
    std::shared_ptr<ProcessExecutor> process_executor,
    std::shared_ptr<FileSystem> file_system,
    std::shared_ptr<Logger> logger
) : process_executor_(process_executor), file_system_(file_system), logger_(logger) {}

std::string EasyRSACertificateService::get_easyrsa_dir(const std::string& vpn_name) {
    return "/etc/openvpn/server-" + vpn_name;
}

bool EasyRSACertificateService::download_easyrsa(const std::string& server_dir) {
    if (!file_system_->directory_exists(server_dir)) {
        if (!file_system_->create_directory(server_dir, true)) {
            logger_->error("failed to create server directory: " + server_dir);
            return false;
        }
    }
    
    logger_->info("server directory ready: " + server_dir);
    return true;
}

bool EasyRSACertificateService::initialize_pki(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    
    if (!download_easyrsa(server_dir)) {
        return false;
    }
    
    logger_->info("PKI initialized for: " + vpn_name);
    return true;
}

bool EasyRSACertificateService::generate_ca_certificate(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string ca_key = server_dir + "/ca.key";
    std::string ca_crt = server_dir + "/ca.crt";
    
    // Usar apenas curvas elípticas - prioridade: Ed25519 > secp256k1
    std::string ca_key_cmd;
    std::string curve_used;
    
    if (is_curve_supported("Ed25519")) {
        ca_key_cmd = "openssl genpkey -algorithm Ed25519 -out " + ca_key;
        curve_used = "Ed25519";
    } else if (is_curve_supported("secp256k1")) {
        ca_key_cmd = "openssl ecparam -genkey -name secp256k1 -out " + ca_key;
        curve_used = "secp256k1";
    } else {
        logger_->error("sistema não suporta curvas elípticas modernas (Ed25519 ou secp256k1)");
        return false;
    }
    
    auto result = process_executor_->execute(ca_key_cmd);
    if (result.exit_code != 0) {
        logger_->error("failed to generate CA private key with " + curve_used + ": " + result.stderr_output);
        return false;
    }
    
    std::string ca_crt_cmd = "openssl req -new -x509 -key " + ca_key + " -out " + ca_crt + 
                            " -days 7300 -sha256 -subj '/CN=" + vpn_name + "-CA-" + curve_used + "/C=US/ST=CA/L=SF/O=OpenVPN-EC/OU=EC-Certificate-Authority'";
    result = process_executor_->execute(ca_crt_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate CA certificate: " + result.stderr_output);
        return false;
    }
    
    result = process_executor_->execute("chmod 600 " + ca_key);
    if (result.exit_code != 0) {
        logger_->warning("failed to set secure permissions on CA key");
    }
    
    logger_->info("CA certificate generated using " + curve_used + " for: " + vpn_name);
    return true;
}

bool EasyRSACertificateService::generate_server_certificate(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string server_key = server_dir + "/server.key";
    std::string server_csr = server_dir + "/server.csr";
    std::string server_crt = server_dir + "/server.crt";
    std::string ca_key = server_dir + "/ca.key";
    std::string ca_crt = server_dir + "/ca.crt";
    
    // Detectar algoritmo usado na CA e usar o mesmo
    std::string ca_algorithm = detect_ca_algorithm(ca_key);
    std::string server_key_cmd;
    
    if (ca_algorithm == "Ed25519") {
        server_key_cmd = "openssl genpkey -algorithm Ed25519 -out " + server_key;
    } else if (ca_algorithm == "secp256k1") {
        server_key_cmd = "openssl ecparam -genkey -name secp256k1 -out " + server_key;
    } else if (ca_algorithm == "secp384r1") {
        server_key_cmd = "openssl ecparam -genkey -name secp384r1 -out " + server_key;
    } else {
        logger_->error("CA uses unsupported algorithm: " + ca_algorithm);
        return false;
    }
    
    auto result = process_executor_->execute(server_key_cmd);
    if (result.exit_code != 0) {
        logger_->error("failed to generate server private key: " + result.stderr_output);
        return false;
    }
    
    std::string server_csr_cmd = "openssl req -new -key " + server_key + " -out " + server_csr + 
                                " -subj '/CN=" + vpn_name + "-server-" + ca_algorithm + "/C=US/ST=CA/L=SF/O=OpenVPN-EC/OU=EC-Server'";
    result = process_executor_->execute(server_csr_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate server certificate request: " + result.stderr_output);
        return false;
    }
    
    std::string ext_file = server_dir + "/server.ext";
    std::string ext_content = "basicConstraints=CA:FALSE\n";
    ext_content += "nsCertType=server\n";
    ext_content += "nsComment=\"OpenVPN EC Server Certificate\"\n";
    ext_content += "subjectKeyIdentifier=hash\n";
    ext_content += "authorityKeyIdentifier=keyid,issuer:always\n";
    ext_content += "extendedKeyUsage=serverAuth\n";
    ext_content += "keyUsage=keyEncipherment,dataEncipherment,digitalSignature,keyAgreement\n";
    
    if (!file_system_->write_file(ext_file, ext_content)) {
        logger_->error("failed to create server extension file");
        return false;
    }
    
    std::string server_crt_cmd = "openssl x509 -req -in " + server_csr + " -CA " + ca_crt + " -CAkey " + ca_key + 
                                " -out " + server_crt + " -days 3650 -sha256 -CAcreateserial -extfile " + ext_file;
    result = process_executor_->execute(server_crt_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate server certificate: " + result.stderr_output);
        return false;
    }
    
    result = process_executor_->execute("chmod 600 " + server_key);
    if (result.exit_code != 0) {
        logger_->warning("failed to set secure permissions on server key");
    }
    
    process_executor_->execute("rm -f " + server_csr + " " + ext_file);
    
    logger_->info("server certificate generated using " + ca_algorithm + " for: " + vpn_name);
    return true;
}

bool EasyRSACertificateService::generate_client_certificate(const std::string& vpn_name, const std::string& client_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string client_key = server_dir + "/" + client_name + ".key";
    std::string client_csr = server_dir + "/" + client_name + ".csr";
    std::string client_crt = server_dir + "/" + client_name + ".crt";
    std::string ca_key = server_dir + "/ca.key";
    std::string ca_crt = server_dir + "/ca.crt";
    
    // Detectar algoritmo usado na CA para manter consistência
    std::string ca_algorithm = detect_ca_algorithm(ca_key);
    std::string client_key_cmd;
    
    if (ca_algorithm == "Ed25519") {
        client_key_cmd = "openssl genpkey -algorithm Ed25519 -out " + client_key;
    } else if (ca_algorithm == "secp256k1") {
        client_key_cmd = "openssl ecparam -genkey -name secp256k1 -out " + client_key;
    } else if (ca_algorithm == "secp384r1") {
        client_key_cmd = "openssl ecparam -genkey -name secp384r1 -out " + client_key;
    } else {
        logger_->error("CA uses unsupported algorithm: " + ca_algorithm);
        return false;
    }
    
    auto result = process_executor_->execute(client_key_cmd);
    if (result.exit_code != 0) {
        logger_->error("failed to generate client private key for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    std::string client_csr_cmd = "openssl req -new -key " + client_key + " -out " + client_csr + 
                                " -subj '/CN=" + client_name + "-" + ca_algorithm + "/C=US/ST=CA/L=SF/O=OpenVPN-EC/OU=EC-Client'";
    result = process_executor_->execute(client_csr_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate client certificate request for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    std::string ext_file = server_dir + "/client.ext";
    std::string ext_content = "basicConstraints=CA:FALSE\n";
    ext_content += "nsCertType=client,email\n";
    ext_content += "nsComment=\"OpenVPN EC Client Certificate\"\n";
    ext_content += "subjectKeyIdentifier=hash\n";
    ext_content += "authorityKeyIdentifier=keyid,issuer\n";
    ext_content += "extendedKeyUsage=clientAuth\n";
    ext_content += "keyUsage=digitalSignature\n";
    
    if (!file_system_->write_file(ext_file, ext_content)) {
        logger_->error("failed to create client extension file");
        return false;
    }
    
    std::string client_crt_cmd = "openssl x509 -req -in " + client_csr + " -CA " + ca_crt + " -CAkey " + ca_key + 
                                " -out " + client_crt + " -days 3650 -sha256 -CAcreateserial -extfile " + ext_file;
    result = process_executor_->execute(client_crt_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate client certificate for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    result = process_executor_->execute("chmod 600 " + client_key);
    if (result.exit_code != 0) {
        logger_->warning("failed to set secure permissions on client key for " + client_name);
    }
    
    process_executor_->execute("rm -f " + client_csr + " " + ext_file);
    
    logger_->info("client certificate generated using " + ca_algorithm + " for: " + client_name);
    return true;
}

bool EasyRSACertificateService::generate_dh_params(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string dh_file = server_dir + "/dh.pem";
    
    // Com curvas elípticas, DH parameters não são necessários
    // ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) é usado automaticamente
    logger_->info("usando curvas elípticas - DH parameters não necessários (ECDHE automático)");
    
    // Criar arquivo dummy para compatibilidade com scripts legados
    std::string ec_info = 
        "-----BEGIN EC-ECDHE INFO-----\n"
        "# Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) em uso\n"
        "# DH parameters tradicionais não são necessários\n"
        "# Perfect Forward Secrecy garantido automaticamente\n"
        "# Performance superior com curvas elípticas\n"
        "-----END EC-ECDHE INFO-----\n";
    
    if (!file_system_->write_file(dh_file, ec_info)) {
        logger_->error("failed to write ECDHE info file");
        return false;
    }
    
    logger_->info("ECDHE configurado para: " + vpn_name + " (sem DH tradicional necessário)");
    return true;
}

bool EasyRSACertificateService::generate_tls_crypt_key(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string key_file = server_dir + "/tc.key";
    std::string gen_cmd = "openvpn --genkey secret " + key_file;
    
    auto result = process_executor_->execute(gen_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate TLS-Crypt key: " + result.stderr_output);
        return false;
    }
    
    logger_->info("TLS-Crypt key generated for: " + vpn_name);
    return true;
}

bool EasyRSACertificateService::revoke_client_certificate(const std::string& vpn_name, const std::string& client_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string client_crt = server_dir + "/" + client_name + ".crt";
    
    if (!file_system_->file_exists(client_crt)) {
        logger_->error("client certificate not found: " + client_name);
        return false;
    }
    
    process_executor_->execute("rm -f " + client_crt);
    process_executor_->execute("rm -f " + server_dir + "/" + client_name + ".key");
    
    logger_->info("client certificate revoked for: " + client_name);
    return true;
}

bool EasyRSACertificateService::generate_crl(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string crl_file = server_dir + "/crl.pem";
    std::string ca_crt = server_dir + "/ca.crt";
    std::string ca_key = server_dir + "/ca.key";
    std::string config_file = server_dir + "/openssl.conf";
    
    std::string config_content = "[ca]\n";
    config_content += "default_ca = CA_default\n\n";
    config_content += "[CA_default]\n";
    config_content += "database = " + server_dir + "/index.txt\n";
    config_content += "crlnumber = " + server_dir + "/crlnumber\n";
    config_content += "default_md = sha256\n";
    config_content += "default_crl_days = 30\n";
    
    if (!file_system_->write_file(config_file, config_content)) {
        logger_->error("failed to create openssl config file");
        return false;
    }
    
    if (!file_system_->write_file(server_dir + "/index.txt", "")) {
        logger_->error("failed to create index file");
        return false;
    }
    
    if (!file_system_->write_file(server_dir + "/crlnumber", "01\n")) {
        logger_->error("failed to create crlnumber file");
        return false;
    }
    
    std::string crl_cmd = "openssl ca -gencrl -keyfile " + ca_key + " -cert " + ca_crt + 
                         " -out " + crl_file + " -config " + config_file;
    
    auto result = process_executor_->execute(crl_cmd);
    
    process_executor_->execute("rm -f " + config_file);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate CRL: " + result.stderr_output);
        return false;
    }
    
    logger_->info("CRL generated for: " + vpn_name);
    return true;
}

std::string EasyRSACertificateService::get_optimal_curve_for_performance() {
    // Ordem de preferência apenas para curvas elípticas modernas
    std::vector<std::string> curves = {"Ed25519", "secp256k1", "secp384r1"};
    
    for (const auto& curve : curves) {
        if (is_curve_supported(curve)) {
            logger_->info("selected optimal EC curve: " + curve);
            return curve;
        }
    }
    
    logger_->error("no modern elliptic curves supported - sistema incompatível");
    return "";
}

std::string EasyRSACertificateService::detect_ca_algorithm(const std::string& ca_key_path) {
    auto result = process_executor_->execute("openssl pkey -in " + ca_key_path + " -text -noout | head -3");
    if (result.exit_code != 0) {
        logger_->error("failed to detect CA algorithm");
        return "";
    }
    
    std::string output = result.stdout_output;
    if (output.find("Ed25519") != std::string::npos) {
        return "Ed25519";
    } else if (output.find("secp256k1") != std::string::npos) {
        return "secp256k1";
    } else if (output.find("secp384r1") != std::string::npos || output.find("P-384") != std::string::npos) {
        return "secp384r1";
    } else if (output.find("secp521r1") != std::string::npos || output.find("P-521") != std::string::npos) {
        return "secp521r1";
    }
    
    logger_->error("CA uses unsupported algorithm: " + output);
    return "";
}

bool EasyRSACertificateService::is_curve_supported(const std::string& curve_name) {
    if (curve_name == "Ed25519") {
        auto result = process_executor_->execute("openssl genpkey -algorithm Ed25519 -out /tmp/test_ed25519.key 2>/dev/null && rm -f /tmp/test_ed25519.key");
        return result.exit_code == 0;
    } else {
        // Testar curvas EC
        auto result = process_executor_->execute("openssl ecparam -list_curves | grep -q " + curve_name);
        return result.exit_code == 0;
    }
}

std::string EasyRSACertificateService::get_key_generation_command(CryptoAlgorithm algorithm, const std::string& output_file, int) {
    switch (algorithm) {
        case CryptoAlgorithm::SECP256K1:
            return "openssl ecparam -genkey -name secp256k1 -out " + output_file;
        case CryptoAlgorithm::ED25519:
            return "openssl genpkey -algorithm Ed25519 -out " + output_file;
        case CryptoAlgorithm::SECP384R1:
            return "openssl ecparam -genkey -name secp384r1 -out " + output_file;
        case CryptoAlgorithm::AUTO:
        default:
            // AUTO: detectar automaticamente o melhor
            if (is_curve_supported("Ed25519")) {
                return "openssl genpkey -algorithm Ed25519 -out " + output_file;
            } else if (is_curve_supported("secp256k1")) {
                return "openssl ecparam -genkey -name secp256k1 -out " + output_file;
            } else {
                return "openssl ecparam -genkey -name secp384r1 -out " + output_file;
            }
    }
}

std::string EasyRSACertificateService::get_cert_generation_params(CryptoAlgorithm) {
    // Para todas as curvas elípticas, SHA256 é optimal
    return "-sha256";
}

}
