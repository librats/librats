package com.librats;

/**
 * Notified when a message arrives on a subscribed pub/sub topic.
 *
 * <p>Register with {@link RatsNode#subscribe(String, TopicCallback)} before
 * {@link RatsNode#start()}. Fires on an internal reactor thread.</p>
 */
@FunctionalInterface
public interface TopicCallback {
    /**
     * @param peerId 64-char lowercase hex of the sending peer's id
     * @param topic  the topic the message was published to
     * @param data   the raw message bytes
     */
    void onTopicMessage(String peerId, String topic, byte[] data);
}
