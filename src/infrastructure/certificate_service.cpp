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
    
    std::string ca_key_cmd = "openssl genpkey -algorithm RSA -out " + ca_key + " -pkeyopt rsa_keygen_bits:4096";
    auto result = process_executor_->execute(ca_key_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate CA private key: " + result.stderr_output);
        return false;
    }
    
    std::string ca_crt_cmd = "openssl req -new -x509 -key " + ca_key + " -out " + ca_crt + 
                            " -days 3650 -subj '/CN=" + vpn_name + "-CA/C=US/ST=CA/L=SF/O=OpenVPN'";
    result = process_executor_->execute(ca_crt_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate CA certificate: " + result.stderr_output);
        return false;
    }
    
    logger_->info("CA certificate generated for: " + vpn_name);
    return true;
}

bool EasyRSACertificateService::generate_server_certificate(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string server_key = server_dir + "/server.key";
    std::string server_csr = server_dir + "/server.csr";
    std::string server_crt = server_dir + "/server.crt";
    std::string ca_key = server_dir + "/ca.key";
    std::string ca_crt = server_dir + "/ca.crt";
    
    std::string server_key_cmd = "openssl genpkey -algorithm RSA -out " + server_key + " -pkeyopt rsa_keygen_bits:2048";
    auto result = process_executor_->execute(server_key_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate server private key: " + result.stderr_output);
        return false;
    }
    
    std::string server_csr_cmd = "openssl req -new -key " + server_key + " -out " + server_csr + 
                                " -subj '/CN=" + vpn_name + "-server/C=US/ST=CA/L=SF/O=OpenVPN'";
    result = process_executor_->execute(server_csr_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate server certificate request: " + result.stderr_output);
        return false;
    }
    
    std::string ext_file = server_dir + "/server.ext";
    if (!file_system_->write_file(ext_file, "extendedKeyUsage=serverAuth\nkeyUsage=keyEncipherment,dataEncipherment,digitalSignature\n")) {
        logger_->error("failed to create server extension file");
        return false;
    }
    
    std::string server_crt_cmd = "openssl x509 -req -in " + server_csr + " -CA " + ca_crt + " -CAkey " + ca_key + 
                                " -out " + server_crt + " -days 3650 -CAcreateserial -extfile " + ext_file;
    result = process_executor_->execute(server_crt_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate server certificate: " + result.stderr_output);
        return false;
    }
    
    process_executor_->execute("rm -f " + server_csr);
    process_executor_->execute("rm -f " + ext_file);
    
    logger_->info("server certificate generated for: " + vpn_name);
    return true;
}

bool EasyRSACertificateService::generate_client_certificate(const std::string& vpn_name, const std::string& client_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string client_key = server_dir + "/" + client_name + ".key";
    std::string client_csr = server_dir + "/" + client_name + ".csr";
    std::string client_crt = server_dir + "/" + client_name + ".crt";
    std::string ca_key = server_dir + "/ca.key";
    std::string ca_crt = server_dir + "/ca.crt";
    
    std::string client_key_cmd = "openssl genpkey -algorithm RSA -out " + client_key + " -pkeyopt rsa_keygen_bits:2048";
    auto result = process_executor_->execute(client_key_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate client private key for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    std::string client_csr_cmd = "openssl req -new -key " + client_key + " -out " + client_csr + 
                                " -subj '/CN=" + client_name + "/C=US/ST=CA/L=SF/O=OpenVPN'";
    result = process_executor_->execute(client_csr_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate client certificate request for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    std::string ext_file = server_dir + "/client.ext";
    if (!file_system_->write_file(ext_file, "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n")) {
        logger_->error("failed to create client extension file");
        return false;
    }
    
    std::string client_crt_cmd = "openssl x509 -req -in " + client_csr + " -CA " + ca_crt + " -CAkey " + ca_key + 
                                " -out " + client_crt + " -days 3650 -CAcreateserial -extfile " + ext_file;
    result = process_executor_->execute(client_crt_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate client certificate for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    process_executor_->execute("rm -f " + client_csr);
    process_executor_->execute("rm -f " + ext_file);
    
    logger_->info("client certificate generated for: " + client_name);
    return true;
}

bool EasyRSACertificateService::generate_dh_params(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string dh_file = server_dir + "/dh.pem";
    std::string dh_cmd = "openssl dhparam -out " + dh_file + " 2048";
    
    auto result = process_executor_->execute(dh_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate DH parameters: " + result.stderr_output);
        return false;
    }
    
    logger_->info("DH parameters generated for: " + vpn_name);
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

}
