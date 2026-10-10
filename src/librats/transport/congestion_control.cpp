#include "librats/transport/congestion_control.h"
#include "librats/transport/bbr.h"
#include "librats/transport/reno.h"

namespace librats {
namespace cc {

std::unique_ptr<CongestionController> make_controller(CongestionAlgorithm algorithm,
                                                      const RttEstimate& rtt,
                                                      const DeliveryRateSampler& sampler,
                                                      Clock::time_point now, uint64_t seed) {
    switch (algorithm) {
        case CongestionAlgorithm::Reno:
            return std::make_unique<RenoController>(rtt, now);
        case CongestionAlgorithm::Bbr:
            break;
    }
    return std::make_unique<BbrController>(rtt, sampler, now, seed);
}

} // namespace cc
} // namespace librats
