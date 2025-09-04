#include "main/dependency_factory.h"
#include <iostream>
#include <cstdlib>
#include <unistd.h>

int main() {
    try {
        if (getuid() != 0) {
            std::cerr << "error: this application must be run as root" << std::endl;
            return 1;
        }
        
        auto controller = openvpn_manager::create_cli_controller();
        controller->run();
        
    } catch (const std::exception& e) {
        std::cerr << "fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
