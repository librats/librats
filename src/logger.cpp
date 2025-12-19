#include "logger.h"

namespace librats {

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

} // namespace librats

