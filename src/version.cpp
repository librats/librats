#include "version.h"
#include <iostream>
#include <iomanip>

namespace librats {
    namespace version {
        
        void print_version_info() {
            std::cout << "Version: " << STRING << std::endl;
            std::cout << "Git: " << GIT_DESCRIBE << std::endl;
            std::cout << "Build: " << BUILD << std::endl;
        }
        
        void print_header() {
            std::cout << ASCII_HEADER << std::endl;
            std::cout << "           Version: " << std::left << std::setw(10) << STRING 
                      << "  Build: " << BUILD << std::endl;
            std::cout << "           Git: " << GIT_DESCRIBE << std::endl;
            std::cout << "        ========================================        " << std::endl;
            std::cout << std::endl;
        }
    }
}
