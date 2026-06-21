package com.librats;

/**
 * Callback invoked when a pub/sub message arrives on a subscribed topic.
 *
 * <p>Register per-topic with {@link RatsClient#subscribe(String, TopicMessageCallback)}
 * before {@link RatsClient#start()}. Requires the pub/sub subsystem
 * ({@link RatsClient#enablePubsub()}). Fires on an internal reactor thread.</p>
 */
public interface TopicMessageCallback {
    /**
     * Called when a message is published to a subscribed topic.
     *
     * @param peerId 64-char lowercase hex of the publishing peer's id
     * @param topic  the topic the message was published on
     * @param data   the raw message bytes
     */
    void onTopicMessage(String peerId, String topic, byte[] data);
}
