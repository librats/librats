#include "bt_choker.h"
#include "bt_peer_connection.h"

#include <algorithm>
#include <random>

namespace librats {

//=============================================================================
// Constructor
//=============================================================================

Choker::Choker()
    : optimistic_peer_(nullptr)
    , optimistic_rotation_index_(0) {
    last_rechoke_ = std::chrono::steady_clock::now();
    last_optimistic_rotation_ = std::chrono::steady_clock::now();
}

Choker::Choker(const ChokerConfig& config)
    : config_(config)
    , optimistic_peer_(nullptr)
    , optimistic_rotation_index_(0) {
    last_rechoke_ = std::chrono::steady_clock::now();
    last_optimistic_rotation_ = std::chrono::steady_clock::now();
}

void Choker::set_config(const ChokerConfig& config) {
    config_ = config;
}

bool Choker::should_rechoke() const {
    auto now = std::chrono::steady_clock::now();
    return (now - last_rechoke_) >= config_.rechoke_interval;
}

//=============================================================================
// Main Choking Algorithm
//=============================================================================

ChokeResult Choker::run(std::vector<ChokePeerInfo>& peers) {
    last_rechoke_ = std::chrono::steady_clock::now();
    
    if (config_.seed_mode) {
        return run_seed_mode(peers);
    } else {
        return run_download_mode(peers);
    }
}

ChokeResult Choker::run_download_mode(std::vector<ChokePeerInfo>& peers) {
    ChokeResult result;
    
    if (peers.empty()) {
        return result;
    }
    
    // Check if we should rotate optimistic unchoke
    auto now = std::chrono::steady_clock::now();
    if ((now - last_optimistic_rotation_) >= config_.optimistic_interval) {
        rotate_optimistic(peers);
    }
    
    // Sort peers by download rate (best first)
    // Only consider peers that are interested in us
    std::vector<ChokePeerInfo*> interested_peers;
    for (auto& peer : peers) {
        if (peer.peer_interested && peer.connection != nullptr) {
            interested_peers.push_back(&peer);
        }
    }
    
    std::sort(interested_peers.begin(), interested_peers.end(),
        [](const ChokePeerInfo* a, const ChokePeerInfo* b) {
            // Prefer peers with higher download rate to us
            return a->download_rate > b->download_rate;
        });
    
    // Determine how many slots we have (excluding optimistic)
    size_t regular_slots = config_.max_uploads;
    if (optimistic_peer_ != nullptr) {
        regular_slots = config_.max_uploads > 0 ? config_.max_uploads - 1 : 0;
    }
    
    // Unchoke the top peers
    size_t unchoked = 0;
    for (auto* peer : interested_peers) {
        if (peer->connection == optimistic_peer_) {
            // Already counted as optimistic
            if (peer->am_choking) {
                result.to_unchoke.push_back(peer->connection);
                peer->am_choking = false;
                peer->last_unchoke = now;
            }
            continue;
        }
        
        if (unchoked < regular_slots) {
            if (peer->am_choking) {
                result.to_unchoke.push_back(peer->connection);
                peer->am_choking = false;
                peer->last_unchoke = now;
            }
            ++unchoked;
        } else {
            if (!peer->am_choking) {
                result.to_choke.push_back(peer->connection);
                peer->am_choking = true;
            }
        }
    }
    
    // Choke peers who are no longer interested
    for (auto& peer : peers) {
        if (!peer.peer_interested && !peer.am_choking && peer.connection != nullptr) {
            // Could optionally keep them unchoked for a bit
            // For now, choke them
            result.to_choke.push_back(peer.connection);
            peer.am_choking = true;
        }
    }
    
    return result;
}

ChokeResult Choker::run_seed_mode(std::vector<ChokePeerInfo>& peers) {
    ChokeResult result;
    
    if (peers.empty()) {
        return result;
    }
    
    auto now = std::chrono::steady_clock::now();
    
    // In seed mode, we prioritize upload rate and round-robin fairness
    // Sort by upload rate, but give some randomness
    std::vector<ChokePeerInfo*> interested_peers;
    for (auto& peer : peers) {
        if (peer.peer_interested && peer.connection != nullptr) {
            interested_peers.push_back(&peer);
        }
    }
    
    // Sort by upload rate (how fast we're uploading to them)
    // and time since last unchoke for fairness
    std::sort(interested_peers.begin(), interested_peers.end(),
        [now](const ChokePeerInfo* a, const ChokePeerInfo* b) {
            // Prioritize peers we haven't unchoked recently
            auto a_time = std::chrono::duration_cast<std::chrono::seconds>(
                now - a->last_unchoke).count();
            auto b_time = std::chrono::duration_cast<std::chrono::seconds>(
                now - b->last_unchoke).count();
            
            // Mix of upload speed and fairness
            double a_score = a->upload_rate + (a_time * 10.0);
            double b_score = b->upload_rate + (b_time * 10.0);
            
            return a_score > b_score;
        });
    
    // Unchoke top N
    size_t unchoked = 0;
    for (auto* peer : interested_peers) {
        if (unchoked < config_.max_uploads) {
            if (peer->am_choking) {
                result.to_unchoke.push_back(peer->connection);
                peer->am_choking = false;
                peer->last_unchoke = now;
            }
            ++unchoked;
        } else {
            if (!peer->am_choking) {
                result.to_choke.push_back(peer->connection);
                peer->am_choking = true;
            }
        }
    }
    
    return result;
}

void Choker::rotate_optimistic(std::vector<ChokePeerInfo>& peers) {
    last_optimistic_rotation_ = std::chrono::steady_clock::now();
    
    // Find peers that are currently choked and interested
    std::vector<ChokePeerInfo*> candidates;
    for (auto& peer : peers) {
        if (peer.am_choking && peer.peer_interested && peer.connection != nullptr) {
            candidates.push_back(&peer);
        }
    }
    
    if (candidates.empty()) {
        optimistic_peer_ = nullptr;
        return;
    }
    
    // Prefer peers that have been connected for a short time (new peers)
    // to give them a chance to prove themselves
    std::sort(candidates.begin(), candidates.end(),
        [](const ChokePeerInfo* a, const ChokePeerInfo* b) {
            return a->connected_at > b->connected_at;  // Newer first
        });
    
    // Pick with some randomness weighted towards newer peers
    size_t index = 0;
    if (candidates.size() > 1) {
        // Prefer first 1/4 of candidates (newer)
        size_t range = std::max(candidates.size() / 4, size_t(1));
        
        static thread_local std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<size_t> dis(0, range - 1);
        index = dis(gen);
    }
    
    ChokePeerInfo* selected = candidates[index];
    selected->is_optimistic = true;
    optimistic_peer_ = selected->connection;
    
    // Clear optimistic flag from previous peer
    for (auto& peer : peers) {
        if (peer.connection != optimistic_peer_) {
            peer.is_optimistic = false;
        }
    }
}

} // namespace librats
