#pragma once

#include "domain/services.h"
#include "infrastructure/interfaces.h"
#include "core/types.h"

namespace openvpn_manager {

class EasyRSACertificateService : public CertificateService {
public:
    EasyRSACertificateService(
        std::shared_ptr<ProcessExecutor> process_executor,
        std::shared_ptr<FileSystem> file_system,
        std::shared_ptr<Logger> logger
    );
    
    bool initialize_pki(const std::string& vpn_name) override;
    bool generate_ca_certificate(const std::string& vpn_name) override;
    bool generate_server_certificate(const std::string& vpn_name) override;
    bool generate_client_certificate(const std::string& vpn_name, const std::string& client_name) override;
    bool revoke_client_certificate(const std::string& vpn_name, const std::string& client_name) override;
    bool generate_crl(const std::string& vpn_name) override;
    bool generate_dh_params(const std::string& vpn_name) override;
    bool generate_tls_crypt_key(const std::string& vpn_name) override;

private:
    std::shared_ptr<ProcessExecutor> process_executor_;
    std::shared_ptr<FileSystem> file_system_;
    std::shared_ptr<Logger> logger_;
    
    std::string get_easyrsa_dir(const std::string& vpn_name);
    bool download_easyrsa(const std::string& easyrsa_dir);
    bool setup_easyrsa_vars(const std::string& easyrsa_dir);
    std::string get_key_generation_command(CryptoAlgorithm algorithm, const std::string& output_file, int key_size = 4096);
    std::string get_cert_generation_params(CryptoAlgorithm algorithm);
    std::string get_optimal_curve_for_performance();
    std::string detect_ca_algorithm(const std::string& ca_key_path);
    bool is_curve_supported(const std::string& curve_name);
};

}
