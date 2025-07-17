#include <gtest/gtest.h>
#include "../src/librats.h"
#include <thread>
#include <chrono>
#include <atomic>

using namespace librats;

class MessageExchangeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create two clients for testing
        client1 = std::make_unique<RatsClient>(8001, 5);
        client2 = std::make_unique<RatsClient>(8002, 5);
        
        // Reset counters
        greeting_count = 0;
        status_count = 0;
        once_count = 0;
        response_received = false;
        
        // Start both clients
        ASSERT_TRUE(client1->start()) << "Failed to start client1";
        ASSERT_TRUE(client2->start()) << "Failed to start client2";
        
        // Wait for initialization
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Connect client2 to client1
        ASSERT_TRUE(client2->connect_to_peer("127.0.0.1", 8001)) << "Failed to connect client2 to client1";
        
        // Wait for handshake to complete
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    void TearDown() override {
        if (client1) {
            client1->stop();
        }
        if (client2) {
            client2->stop();
        }
    }
    
    std::unique_ptr<RatsClient> client1;
    std::unique_ptr<RatsClient> client2;
    
    // Counters for testing
    std::atomic<int> greeting_count{0};
    std::atomic<int> status_count{0};
    std::atomic<int> once_count{0};
    std::atomic<bool> response_received{false};
};

TEST_F(MessageExchangeTest, BasicConnectionAndSetup) {
    EXPECT_TRUE(client1->is_running());
    EXPECT_TRUE(client2->is_running());
    EXPECT_EQ(client1->get_peer_count(), 1);
    EXPECT_EQ(client2->get_peer_count(), 1);
}

TEST_F(MessageExchangeTest, MessageHandlerRegistration) {
    // Set up message handlers on client1
    client1->on("greeting", [this](const std::string& peer_id, const nlohmann::json& data) {
        EXPECT_FALSE(peer_id.empty());
        EXPECT_TRUE(data.contains("message"));
        greeting_count++;
        
        // Send a response
        nlohmann::json response;
        response["message"] = "Hello back from client1!";
        response["original_sender"] = peer_id;
        client1->send(peer_id, "greeting_response", response);
    });
    
    client1->on("status", [this](const std::string& peer_id, const nlohmann::json& data) {
        EXPECT_FALSE(peer_id.empty());
        EXPECT_TRUE(data.contains("status"));
        status_count++;
    });
    
    client1->once("test_once", [this](const std::string& peer_id, const nlohmann::json& data) {
        EXPECT_FALSE(peer_id.empty());
        EXPECT_TRUE(data.contains("message"));
        once_count++;
    });
    
    // Set up handlers on client2
    client2->on("greeting_response", [this](const std::string& peer_id, const nlohmann::json& data) {
        EXPECT_FALSE(peer_id.empty());
        EXPECT_TRUE(data.contains("message"));
        response_received = true;
    });
    
    // Handlers should be registered (we can't directly test this, but the subsequent tests will validate)
    SUCCEED() << "Message handlers registered successfully";
}

TEST_F(MessageExchangeTest, GreetingMessageExchange) {
    // Set up handlers
    client1->on("greeting", [this](const std::string& peer_id, const nlohmann::json& data) {
        greeting_count++;
        
        // Send a response
        nlohmann::json response;
        response["message"] = "Hello back from client1!";
        response["original_sender"] = peer_id;
        client1->send(peer_id, "greeting_response", response);
    });
    
    client2->on("greeting_response", [this](const std::string& peer_id, const nlohmann::json& data) {
        response_received = true;
    });
    
    // Send greeting message
    nlohmann::json greeting_data;
    greeting_data["message"] = "Hello from client2!";
    greeting_data["sender"] = "test_client2";
    
    bool send_success = false;
    client2->send("greeting", greeting_data, [&send_success](bool success, const std::string& error) {
        send_success = success;
        if (!success) {
            ADD_FAILURE() << "Failed to send greeting: " << error;
        }
    });
    
    // Wait for message processing
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    EXPECT_TRUE(send_success);
    EXPECT_EQ(greeting_count.load(), 1);
    EXPECT_TRUE(response_received.load());
}

TEST_F(MessageExchangeTest, StatusMessageSending) {
    // Set up status handler
    client1->on("status", [this](const std::string& peer_id, const nlohmann::json& data) {
        EXPECT_EQ(data.value("status", ""), "online");
        EXPECT_EQ(data.value("details", ""), "Testing message exchange API");
        status_count++;
    });
    
    // Send status message
    nlohmann::json status_data;
    status_data["status"] = "online";
    status_data["details"] = "Testing message exchange API";
    
    client2->send("status", status_data);
    
    // Wait for message processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_EQ(status_count.load(), 1);
}

TEST_F(MessageExchangeTest, OnceHandlerBehavior) {
    // Set up once handler
    client1->once("test_once", [this](const std::string& peer_id, const nlohmann::json& data) {
        once_count++;
    });
    
    // Send once message multiple times
    nlohmann::json once_data;
    once_data["message"] = "This should only be handled once";
    
    client2->send("test_once", once_data);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    client2->send("test_once", once_data);  // Second call should not trigger handler
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    client2->send("test_once", once_data);  // Third call should not trigger handler
    
    // Wait for message processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_EQ(once_count.load(), 1) << "Once handler should only trigger once, but triggered " << once_count.load() << " times";
}

TEST_F(MessageExchangeTest, HandlerRemoval) {
    // Set up greeting handler
    client1->on("greeting", [this](const std::string& peer_id, const nlohmann::json& data) {
        greeting_count++;
    });
    
    // Send first greeting (should be handled)
    nlohmann::json greeting_data;
    greeting_data["message"] = "First greeting";
    client2->send("greeting", greeting_data);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(greeting_count.load(), 1);
    
    // Remove handler
    client1->off("greeting");
    
    // Send second greeting (should not be handled)
    greeting_data["message"] = "Second greeting should not be handled";
    client2->send("greeting", greeting_data);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Count should still be 1 (not incremented by second message)
    EXPECT_EQ(greeting_count.load(), 1) << "Handler was not properly removed";
}

TEST_F(MessageExchangeTest, TargetedMessageSending) {
    std::atomic<bool> targeted_message_received{false};
    std::string received_peer_id;
    
    // Set up handler on client1
    client1->on("targeted_test", [&](const std::string& peer_id, const nlohmann::json& data) {
        targeted_message_received = true;
        received_peer_id = peer_id;
    });
    
    // Get client1's peer ID as seen by client2
    auto client1_peers = client2->get_validated_peers();
    ASSERT_FALSE(client1_peers.empty()) << "No validated peers found";
    
    std::string target_peer_id = client1_peers[0].peer_id;
    
    // Send targeted message
    nlohmann::json targeted_data;
    targeted_data["message"] = "This is a targeted message";
    targeted_data["target"] = target_peer_id;
    
    client2->send(target_peer_id, "targeted_test", targeted_data);
    
    // Wait for message processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_TRUE(targeted_message_received.load());
    EXPECT_FALSE(received_peer_id.empty());
}

TEST_F(MessageExchangeTest, BroadcastMessageSending) {
    std::atomic<int> broadcast_count{0};
    
    // Set up handler on client1
    client1->on("broadcast_test", [&](const std::string& peer_id, const nlohmann::json& data) {
        broadcast_count++;
    });
    
    // Send broadcast message (should reach client1)
    nlohmann::json broadcast_data;
    broadcast_data["message"] = "This is a broadcast message";
    broadcast_data["type"] = "broadcast";
    
    client2->send("broadcast_test", broadcast_data);
    
    // Wait for message processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_EQ(broadcast_count.load(), 1);
}

TEST_F(MessageExchangeTest, MessageWithCallback) {
    bool callback_called = false;
    bool callback_success = false;
    std::string callback_error;
    
    // Set up handler
    client1->on("callback_test", [](const std::string& peer_id, const nlohmann::json& data) {
        // Just receive the message
    });
    
    // Send message with callback
    nlohmann::json callback_data;
    callback_data["message"] = "Testing callback functionality";
    
    client2->send("callback_test", callback_data, [&](bool success, const std::string& error) {
        callback_called = true;
        callback_success = success;
        callback_error = error;
    });
    
    // Wait for callback
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(callback_success);
    EXPECT_TRUE(callback_error.empty());
}

TEST_F(MessageExchangeTest, InvalidPeerIdCallback) {
    bool callback_called = false;
    bool callback_success = false;
    std::string callback_error;
    
    // Send message to non-existent peer
    nlohmann::json test_data;
    test_data["message"] = "This should fail";
    
    client2->send("non_existent_peer_id", "test_message", test_data, [&](bool success, const std::string& error) {
        callback_called = true;
        callback_success = success;
        callback_error = error;
    });
    
    // Wait for callback
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(callback_success);
    EXPECT_FALSE(callback_error.empty());
    EXPECT_TRUE(callback_error.find("Peer not found") != std::string::npos) << "Expected 'Peer not found' in error message: " << callback_error;
}
