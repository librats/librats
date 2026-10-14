package com.librats;

/**
 * Handed the messages published to a subscribed topic.
 *
 * <p>Register with {@link RatsNode#subscribe(String, TopicCallback)}. Runs on a
 * reactor thread.</p>
 */
@FunctionalInterface
public interface TopicCallback {
    /**
     * @param peerId the sender
     * @param topic  the topic
     * @param data   the message bytes
     */
    void onTopicMessage(String peerId, String topic, byte[] data);
}
