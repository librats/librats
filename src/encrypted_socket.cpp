#include "encrypted_socket.h"
#include "logger.h"
#include <algorithm>
#include <cstring>

#define LOG_ENCRYPT_DEBUG(message) LOG_DEBUG("encrypt", message)
#define LOG_ENCRYPT_INFO(message)  LOG_INFO("encrypt", message)
#define LOG_ENCRYPT_WARN(message)  LOG_WARN("encrypt", message)
#define LOG_ENCRYPT_ERROR(message) LOG_ERROR("encrypt", message)

namespace librats {

// Message framing constants
constexpr uint32_t NOISE_MESSAGE_MAGIC = 0x4E4F4953; // "NOIS" in little endian
constexpr uint32_t HANDSHAKE_MESSAGE_MAGIC = 0x48534B48; // "HSKH" in little endian
constexpr size_t MESSAGE_HEADER_SIZE = 8; // 4 bytes magic + 4 bytes length

//=============================================================================
// EncryptedSocket Implementation
//=============================================================================

EncryptedSocket::EncryptedSocket() = default;

EncryptedSocket::~EncryptedSocket() {
    clear_all_sockets();
}

bool EncryptedSocket::initialize_as_initiator(socket_t socket, const NoiseKey& static_private_key) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto session = std::make_unique<SocketSession>(socket);
    if (!session->session->initialize_as_initiator(static_private_key)) {
        LOG_ENCRYPT_ERROR("Failed to initialize noise session as initiator for socket " << socket);
        return false;
    }
    
    session->is_encrypted = true;
    sessions_[socket] = std::move(session);
    
    LOG_ENCRYPT_INFO("Initialized encrypted socket " << socket << " as initiator");
    return true;
}

bool EncryptedSocket::initialize_as_responder(socket_t socket, const NoiseKey& static_private_key) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto session = std::make_unique<SocketSession>(socket);
    if (!session->session->initialize_as_responder(static_private_key)) {
        LOG_ENCRYPT_ERROR("Failed to initialize noise session as responder for socket " << socket);
        return false;
    }
    
    session->is_encrypted = true;
    sessions_[socket] = std::move(session);
    
    LOG_ENCRYPT_INFO("Initialized encrypted socket " << socket << " as responder");
    return true;
}

bool EncryptedSocket::is_encrypted(socket_t socket) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto* session = get_session(socket);
    return session && session->is_encrypted;
}

bool EncryptedSocket::is_handshake_completed(socket_t socket) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto* session = get_session(socket);
    return session && session->session->is_handshake_completed();
}

bool EncryptedSocket::has_handshake_failed(socket_t socket) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto* session = get_session(socket);
    return session && session->session->has_handshake_failed();
}

bool EncryptedSocket::send_handshake_message(socket_t socket, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto* session = get_session(socket);
    if (!session) {
        LOG_ENCRYPT_ERROR("No session found for socket " << socket);
        return false;
    }
    
    try {
        auto handshake_data = session->session->create_handshake_message(payload);
        if (handshake_data.empty() && !session->session->is_handshake_completed()) {
            LOG_ENCRYPT_ERROR("Failed to create handshake message for socket " << socket);
            return false;
        }
        
        if (!handshake_data.empty()) {
            auto framed_message = frame_message(handshake_data);
            
            // Add handshake magic to distinguish from regular messages
            std::vector<uint8_t> handshake_message;
            handshake_message.resize(4);
            std::memcpy(handshake_message.data(), &HANDSHAKE_MESSAGE_MAGIC, 4);
            handshake_message.insert(handshake_message.end(), framed_message.begin(), framed_message.end());
            
            std::string data_str(handshake_message.begin(), handshake_message.end());
            int sent = send_tcp_data(socket, data_str);
            
            if (sent <= 0) {
                LOG_ENCRYPT_ERROR("Failed to send handshake message to socket " << socket);
                return false;
            }
            
            LOG_ENCRYPT_DEBUG("Sent handshake message (" << handshake_data.size() << " bytes) to socket " << socket);
        }
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_ENCRYPT_ERROR("Exception in send_handshake_message: " << e.what());
        return false;
    }
}

std::vector<uint8_t> EncryptedSocket::receive_handshake_message(socket_t socket) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto* session = get_session(socket);
    if (!session) {
        LOG_ENCRYPT_ERROR("No session found for socket " << socket);
        return {};
    }
    
    try {
        // Receive raw data
        std::string raw_data = receive_tcp_data(socket, 4096);
        if (raw_data.empty()) {
            return {};
        }
        
        std::vector<uint8_t> data(raw_data.begin(), raw_data.end());
        
        // Check for handshake magic
        if (data.size() < 4) {
            LOG_ENCRYPT_WARN("Received data too short for handshake magic");
            return {};
        }
        
        uint32_t received_magic;
        std::memcpy(&received_magic, data.data(), 4);
        
        if (received_magic != HANDSHAKE_MESSAGE_MAGIC) {
            LOG_ENCRYPT_WARN("Received data is not a handshake message (magic: 0x" << std::hex << received_magic << ")");
            return {};
        }
        
        // Remove magic and unframe message
        std::vector<uint8_t> framed_data(data.begin() + 4, data.end());
        auto handshake_data = unframe_message(framed_data);
        
        if (handshake_data.empty()) {
            LOG_ENCRYPT_ERROR("Failed to unframe handshake message");
            return {};
        }
        
        // Process handshake message
        auto payload = session->session->process_handshake_message(handshake_data);
        
        LOG_ENCRYPT_DEBUG("Received and processed handshake message (" << handshake_data.size() << " bytes) from socket " << socket);
        
        return payload;
        
    } catch (const std::exception& e) {
        LOG_ENCRYPT_ERROR("Exception in receive_handshake_message: " << e.what());
        return {};
    }
}

bool EncryptedSocket::send_encrypted_data(socket_t socket, const std::string& data) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto* session = get_session(socket);
    if (!session) {
        LOG_ENCRYPT_ERROR("No session found for socket " << socket);
        return false;
    }
    
    if (!session->session->is_handshake_completed()) {
        LOG_ENCRYPT_ERROR("Cannot send encrypted data: handshake not completed for socket " << socket);
        return false;
    }
    
    try {
        std::vector<uint8_t> plaintext(data.begin(), data.end());
        auto encrypted_data = session->session->encrypt_transport_message(plaintext);
        
        if (encrypted_data.empty()) {
            LOG_ENCRYPT_ERROR("Failed to encrypt data for socket " << socket);
            return false;
        }
        
        auto framed_message = frame_message(encrypted_data);
        std::string frame_str(framed_message.begin(), framed_message.end());
        
        int sent = send_tcp_data(socket, frame_str);
        if (sent <= 0) {
            LOG_ENCRYPT_ERROR("Failed to send encrypted data to socket " << socket);
            return false;
        }
        
        LOG_ENCRYPT_DEBUG("Sent encrypted data (" << data.size() << " bytes plaintext, " << encrypted_data.size() << " bytes encrypted) to socket " << socket);
        return true;
        
    } catch (const std::exception& e) {
        LOG_ENCRYPT_ERROR("Exception in send_encrypted_data: " << e.what());
        return false;
    }
}

std::string EncryptedSocket::receive_encrypted_data(socket_t socket) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto* session = get_session(socket);
    if (!session) {
        LOG_ENCRYPT_ERROR("No session found for socket " << socket);
        return "";
    }
    
    if (!session->session->is_handshake_completed()) {
        LOG_ENCRYPT_ERROR("Cannot receive encrypted data: handshake not completed for socket " << socket);
        return "";
    }
    
    try {
        std::string raw_data = receive_tcp_data(socket, 4096);
        if (raw_data.empty()) {
            return "";
        }
        
        std::vector<uint8_t> framed_data(raw_data.begin(), raw_data.end());
        auto encrypted_data = unframe_message(framed_data);
        
        if (encrypted_data.empty()) {
            LOG_ENCRYPT_ERROR("Failed to unframe encrypted message");
            return "";
        }
        
        auto decrypted_data = session->session->decrypt_transport_message(encrypted_data);
        
        if (decrypted_data.empty()) {
            LOG_ENCRYPT_ERROR("Failed to decrypt data from socket " << socket);
            return "";
        }
        
        std::string result(decrypted_data.begin(), decrypted_data.end());
        LOG_ENCRYPT_DEBUG("Received encrypted data (" << encrypted_data.size() << " bytes encrypted, " << result.size() << " bytes plaintext) from socket " << socket);
        
        return result;
        
    } catch (const std::exception& e) {
        LOG_ENCRYPT_ERROR("Exception in receive_encrypted_data: " << e.what());
        return "";
    }
}

bool EncryptedSocket::send_unencrypted_data(socket_t socket, const std::string& data) {
    int sent = send_tcp_data(socket, data);
    return sent > 0;
}

std::string EncryptedSocket::receive_unencrypted_data(socket_t socket) {
    return receive_tcp_data(socket);
}

void EncryptedSocket::remove_socket(socket_t socket) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(socket);
    if (it != sessions_.end()) {
        LOG_ENCRYPT_DEBUG("Removing encrypted socket session for socket " << socket);
        sessions_.erase(it);
    }
}

void EncryptedSocket::clear_all_sockets() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    LOG_ENCRYPT_INFO("Clearing all encrypted socket sessions (" << sessions_.size() << " sessions)");
    sessions_.clear();
}

NoiseKey EncryptedSocket::generate_static_key() {
    return noise_utils::generate_static_keypair();
}

std::string EncryptedSocket::key_to_string(const NoiseKey& key) {
    return noise_utils::key_to_hex(key);
}

NoiseKey EncryptedSocket::string_to_key(const std::string& key_str) {
    return noise_utils::hex_to_key(key_str);
}

NoiseRole EncryptedSocket::get_socket_role(socket_t socket) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto* session = get_session(socket);
    if (session) {
        return session->session->get_role();
    }
    return NoiseRole::INITIATOR; // Default
}

const NoiseKey& EncryptedSocket::get_remote_static_key(socket_t socket) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    const auto* session = get_session(socket);
    if (session) {
        return session->session->get_remote_static_public_key();
    }
    static NoiseKey empty_key;
    empty_key.fill(0);
    return empty_key;
}

EncryptedSocket::SocketSession* EncryptedSocket::get_session(socket_t socket) {
    auto it = sessions_.find(socket);
    return (it != sessions_.end()) ? it->second.get() : nullptr;
}

const EncryptedSocket::SocketSession* EncryptedSocket::get_session(socket_t socket) const {
    auto it = sessions_.find(socket);
    return (it != sessions_.end()) ? it->second.get() : nullptr;
}

std::vector<uint8_t> EncryptedSocket::frame_message(const std::vector<uint8_t>& message) {
    std::vector<uint8_t> framed(MESSAGE_HEADER_SIZE + message.size());
    
    // Add magic number
    std::memcpy(framed.data(), &NOISE_MESSAGE_MAGIC, 4);
    
    // Add message length
    uint32_t length = static_cast<uint32_t>(message.size());
    std::memcpy(framed.data() + 4, &length, 4);
    
    // Add message data
    std::memcpy(framed.data() + MESSAGE_HEADER_SIZE, message.data(), message.size());
    
    return framed;
}

std::vector<uint8_t> EncryptedSocket::unframe_message(const std::vector<uint8_t>& framed_message) {
    if (framed_message.size() < MESSAGE_HEADER_SIZE) {
        return {};
    }
    
    // Check magic number
    uint32_t magic;
    std::memcpy(&magic, framed_message.data(), 4);
    if (magic != NOISE_MESSAGE_MAGIC) {
        return {};
    }
    
    // Get message length
    uint32_t length;
    std::memcpy(&length, framed_message.data() + 4, 4);
    
    if (length > NOISE_MAX_MESSAGE_SIZE || framed_message.size() < MESSAGE_HEADER_SIZE + length) {
        return {};
    }
    
    // Extract message
    std::vector<uint8_t> message(length);
    std::memcpy(message.data(), framed_message.data() + MESSAGE_HEADER_SIZE, length);
    
    return message;
}

bool EncryptedSocket::is_noise_handshake_message(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return false;
    }
    
    uint32_t magic;
    std::memcpy(&magic, data.data(), 4);
    return magic == HANDSHAKE_MESSAGE_MAGIC;
}

//=============================================================================
// EncryptedSocketManager Implementation
//=============================================================================

EncryptedSocketManager::EncryptedSocketManager() : encryption_enabled_(true) {
    // Generate a default static key
    static_key_ = noise_utils::generate_static_keypair();
    LOG_ENCRYPT_INFO("Generated default static key for encrypted socket manager");
}

EncryptedSocketManager::~EncryptedSocketManager() {
    cleanup_all_sockets();
}

EncryptedSocketManager& EncryptedSocketManager::getInstance() {
    static EncryptedSocketManager instance;
    return instance;
}

bool EncryptedSocketManager::initialize_socket_as_initiator(socket_t socket, const NoiseKey& static_private_key) {
    return encrypted_socket_.initialize_as_initiator(socket, static_private_key);
}

bool EncryptedSocketManager::initialize_socket_as_responder(socket_t socket, const NoiseKey& static_private_key) {
    return encrypted_socket_.initialize_as_responder(socket, static_private_key);
}

bool EncryptedSocketManager::send_data(socket_t socket, const std::string& data) {
    if (!encryption_enabled_) {
        return encrypted_socket_.send_unencrypted_data(socket, data);
    }
    
    if (encrypted_socket_.is_handshake_completed(socket)) {
        return encrypted_socket_.send_encrypted_data(socket, data);
    } else {
        LOG_ENCRYPT_WARN("Attempting to send data on socket " << socket << " before handshake completion");
        return false;
    }
}

std::string EncryptedSocketManager::receive_data(socket_t socket) {
    if (!encryption_enabled_) {
        return encrypted_socket_.receive_unencrypted_data(socket);
    }
    
    if (encrypted_socket_.is_handshake_completed(socket)) {
        return encrypted_socket_.receive_encrypted_data(socket);
    } else {
        LOG_ENCRYPT_WARN("Attempting to receive data on socket " << socket << " before handshake completion");
        return "";
    }
}

bool EncryptedSocketManager::perform_handshake_step(socket_t socket, const std::vector<uint8_t>& received_data) {
    if (!encryption_enabled_) {
        return true; // No handshake needed when encryption is disabled
    }
    
    if (encrypted_socket_.is_handshake_completed(socket)) {
        return true; // Already completed
    }
    
    if (encrypted_socket_.has_handshake_failed(socket)) {
        return false; // Already failed
    }
    
    try {
        if (received_data.empty()) {
            // This is an outgoing handshake message
            return encrypted_socket_.send_handshake_message(socket);
        } else {
            // Process received handshake message
            auto payload = encrypted_socket_.receive_handshake_message(socket);
            
            // If we received a handshake message and we're the responder, 
            // we might need to send a response
            if (!encrypted_socket_.is_handshake_completed(socket)) {
                NoiseRole role = encrypted_socket_.get_socket_role(socket);
                if (role == NoiseRole::RESPONDER) {
                    return encrypted_socket_.send_handshake_message(socket);
                }
            }
            
            return !encrypted_socket_.has_handshake_failed(socket);
        }
        
    } catch (const std::exception& e) {
        LOG_ENCRYPT_ERROR("Exception in perform_handshake_step: " << e.what());
        return false;
    }
}

bool EncryptedSocketManager::is_handshake_completed(socket_t socket) const {
    if (!encryption_enabled_) {
        return true; // No handshake needed when encryption is disabled
    }
    
    return encrypted_socket_.is_handshake_completed(socket);
}

bool EncryptedSocketManager::has_handshake_failed(socket_t socket) const {
    if (!encryption_enabled_) {
        return false; // No handshake to fail when encryption is disabled
    }
    
    return encrypted_socket_.has_handshake_failed(socket);
}

void EncryptedSocketManager::remove_socket(socket_t socket) {
    encrypted_socket_.remove_socket(socket);
}

void EncryptedSocketManager::cleanup_all_sockets() {
    encrypted_socket_.clear_all_sockets();
}

//=============================================================================
// High-level encrypted communication functions
//=============================================================================

namespace encrypted_communication {

bool initialize_encryption(const NoiseKey& static_key) {
    auto& manager = EncryptedSocketManager::getInstance();
    manager.set_static_key(static_key);
    manager.set_encryption_enabled(true);
    
    LOG_ENCRYPT_INFO("Initialized encryption with provided static key");
    return true;
}

NoiseKey generate_node_key() {
    NoiseKey key = EncryptedSocket::generate_static_key();
    LOG_ENCRYPT_INFO("Generated new node static key: " << EncryptedSocket::key_to_string(key));
    return key;
}

void set_encryption_enabled(bool enabled) {
    auto& manager = EncryptedSocketManager::getInstance();
    manager.set_encryption_enabled(enabled);
    
    LOG_ENCRYPT_INFO("Encryption " << (enabled ? "enabled" : "disabled"));
}

bool is_encryption_enabled() {
    auto& manager = EncryptedSocketManager::getInstance();
    return manager.is_encryption_enabled();
}

int send_tcp_data_encrypted(socket_t socket, const std::string& data) {
    auto& manager = EncryptedSocketManager::getInstance();
    
    if (manager.send_data(socket, data)) {
        return static_cast<int>(data.size());
    }
    return -1;
}

std::string receive_tcp_data_encrypted(socket_t socket, size_t buffer_size) {
    auto& manager = EncryptedSocketManager::getInstance();
    return manager.receive_data(socket);
}

bool initialize_outgoing_connection(socket_t socket) {
    auto& manager = EncryptedSocketManager::getInstance();
    
    if (!manager.is_encryption_enabled()) {
        return true; // No initialization needed when encryption is disabled
    }
    
    bool success = manager.initialize_socket_as_initiator(socket, manager.get_static_key());
    if (success) {
        LOG_ENCRYPT_INFO("Initialized outgoing encrypted connection for socket " << socket);
        
        // Perform initial handshake step
        success = manager.perform_handshake_step(socket);
        if (!success) {
            LOG_ENCRYPT_ERROR("Failed initial handshake step for outgoing connection on socket " << socket);
        }
    }
    
    return success;
}

bool initialize_incoming_connection(socket_t socket) {
    auto& manager = EncryptedSocketManager::getInstance();
    
    if (!manager.is_encryption_enabled()) {
        return true; // No initialization needed when encryption is disabled
    }
    
    bool success = manager.initialize_socket_as_responder(socket, manager.get_static_key());
    if (success) {
        LOG_ENCRYPT_INFO("Initialized incoming encrypted connection for socket " << socket);
    }
    
    return success;
}

bool perform_handshake(socket_t socket) {
    auto& manager = EncryptedSocketManager::getInstance();
    return manager.perform_handshake_step(socket);
}

bool is_handshake_completed(socket_t socket) {
    auto& manager = EncryptedSocketManager::getInstance();
    return manager.is_handshake_completed(socket);
}

void cleanup_socket(socket_t socket) {
    auto& manager = EncryptedSocketManager::getInstance();
    manager.remove_socket(socket);
}

} // namespace encrypted_communication

} // namespace librats 