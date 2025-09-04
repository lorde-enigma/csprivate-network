#include "domain/use_cases.h"
#include "domain/services.h"
#include "infrastructure/file_system_repository.h"
#include "infrastructure/logger.h"
#include "presentation/cli_controller.h"
#include <memory>

namespace openvpn_manager {

class LinuxNetworkService;
class LinuxSystemService;
class LinuxConfigurationService;

std::shared_ptr<CLIController> create_cli_controller();

}
