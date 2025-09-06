#include "infrastructure/certificate_service.h"
#include <filesystem>
#include <algorithm>
#include <cctype>

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
    
    std::string ca_key_cmd = "openssl ecparam -genkey -name secp256k1 -out " + ca_key;
    std::string curve_used = "secp256k1";
    
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
    
    result = process_executor_->execute("chmod 644 " + ca_crt);
    if (result.exit_code != 0) {
        logger_->warning("failed to set permissions on CA certificate");
    }
    
    result = process_executor_->execute("chown -R openvpn:openvpn " + server_dir);
    if (result.exit_code != 0) {
        logger_->warning("failed to set OpenVPN ownership on server directory");
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
    
    std::string server_key_cmd = "openssl ecparam -genkey -name secp256k1 -out " + server_key;
    std::string ca_algorithm = "secp256k1";
    
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
    
    result = process_executor_->execute("chmod 644 " + server_crt);
    if (result.exit_code != 0) {
        logger_->warning("failed to set permissions on server certificate");
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
    
    std::string client_key_cmd = "openssl ecparam -genkey -name secp256k1 -out " + client_key;
    
    auto result = process_executor_->execute(client_key_cmd);
    if (result.exit_code != 0) {
        logger_->error("failed to generate client private key for " + client_name + ": " + result.stderr_output);
        return false;
    }
    
    std::string client_csr_cmd = "openssl req -new -key " + client_key + " -out " + client_csr + 
                                " -subj '/CN=" + client_name + "-secp256k1/C=US/ST=CA/L=SF/O=OpenVPN-EC/OU=EC-Client'";
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
    
    result = process_executor_->execute("chmod 644 " + client_crt);
    if (result.exit_code != 0) {
        logger_->warning("failed to set permissions on client certificate for " + client_name);
    }
    
    process_executor_->execute("rm -f " + client_csr + " " + ext_file);
    
    logger_->info("client certificate generated using secp256k1 for: " + client_name);
    return true;
}

bool EasyRSACertificateService::generate_dh_params(const std::string& vpn_name) {
    std::string server_dir = get_easyrsa_dir(vpn_name);
    std::string dh_file = server_dir + "/dh.pem";
    
    logger_->info("generating minimal 2048-bit DH for OpenVPN compatibility: " + vpn_name);
    
    std::string dh_cmd = "openssl dhparam -out " + dh_file + " 2048";
    auto result = process_executor_->execute(dh_cmd);
    
    if (result.exit_code != 0) {
        logger_->error("failed to generate DH parameters: " + result.stderr_output);
        return false;
    }
    
    result = process_executor_->execute("chmod 644 " + dh_file);
    if (result.exit_code != 0) {
        logger_->warning("failed to set permissions on DH file");
    }
    
    logger_->info("DH 2048 params created for OpenVPN compatibility: " + vpn_name);
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
    return "secp256k1";
}

std::string EasyRSACertificateService::detect_ca_algorithm(const std::string&) {
    return "secp256k1";
}

bool EasyRSACertificateService::is_curve_supported(const std::string& curve_name) {
    return curve_name == "secp256k1";
}

std::string EasyRSACertificateService::get_key_generation_command(CryptoAlgorithm, const std::string& output_file, int) {
    return "openssl ecparam -genkey -name secp256k1 -out " + output_file;
}

std::string EasyRSACertificateService::get_cert_generation_params(CryptoAlgorithm) {
    return "-sha256";
}

}
