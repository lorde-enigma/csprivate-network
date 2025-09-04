#include "main/dependency_factory.h"
#include "infrastructure/linux_implementations.h"
#include "infrastructure/certificate_service.h"
#include "infrastructure/linux_services.h"
#include <memory>

namespace openvpn_manager {

std::shared_ptr<CLIController> create_cli_controller() {
    auto logger = std::make_shared<ConsoleLogger>();
    auto file_system = std::make_shared<LinuxFileSystem>();
    auto process_executor = std::make_shared<LinuxProcessExecutor>();
    
    auto repository = std::make_shared<FileSystemVPNRepository>(file_system, logger);
    auto cert_service = std::make_shared<EasyRSACertificateService>(process_executor, file_system, logger);
    auto network_service = std::make_shared<LinuxNetworkService>(process_executor, file_system, logger);
    auto system_service = std::make_shared<LinuxSystemService>(process_executor, logger);
    auto config_service = std::make_shared<LinuxConfigurationService>(file_system, process_executor, logger);
    
    auto create_vpn_use_case = std::make_shared<CreateVPNUseCase>(
        repository, cert_service, network_service, system_service, config_service
    );
    auto add_client_use_case = std::make_shared<AddClientUseCase>(
        repository, cert_service, config_service
    );
    auto revoke_client_use_case = std::make_shared<RevokeClientUseCase>(
        repository, cert_service
    );
    auto remove_vpn_use_case = std::make_shared<RemoveVPNUseCase>(
        repository, network_service, system_service
    );
    auto list_vpns_use_case = std::make_shared<ListVPNsUseCase>(
        repository, system_service
    );
    auto manage_service_use_case = std::make_shared<ManageServiceUseCase>(system_service);
    
    return std::make_shared<CLIController>(
        create_vpn_use_case,
        add_client_use_case,
        revoke_client_use_case,
        remove_vpn_use_case,
        list_vpns_use_case,
        manage_service_use_case,
        network_service,
        logger
    );
}

}
