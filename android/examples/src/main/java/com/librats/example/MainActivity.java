package com.librats.example;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.librats.CloseReason;
import com.librats.LogLevel;
import com.librats.PeerInfo;
import com.librats.RatsException;
import com.librats.RatsNode;

import java.nio.charset.StandardCharsets;

/**
 * Minimal librats chat: start a node, dial a peer or find one over mDNS, and
 * broadcast on a channel.
 *
 * <p>Every callback and every {@code enable*} is set up while the node is still
 * stopped, and since callbacks arrive on a reactor thread, each one hops to the UI
 * thread before touching a view.</p>
 */
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "LibRatsExample";

    /** Application channel this demo uses for chat messages. */
    private static final String CHAT_CHANNEL = "chat";

    private RatsNode node;
    private WifiManager.MulticastLock multicastLock;
    private TextView statusText;
    private TextView messagesText;
    private EditText hostInput;
    private EditText portInput;
    private EditText messageInput;
    private Button startButton;
    private Button connectButton;
    private Button sendButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        setupNode();
    }

    private void initViews() {
        statusText = findViewById(R.id.statusText);
        messagesText = findViewById(R.id.messagesText);
        hostInput = findViewById(R.id.hostInput);
        portInput = findViewById(R.id.portInput);
        messageInput = findViewById(R.id.messageInput);
        startButton = findViewById(R.id.startButton);
        connectButton = findViewById(R.id.connectButton);
        sendButton = findViewById(R.id.sendButton);

        startButton.setOnClickListener(this::onStartClicked);
        connectButton.setOnClickListener(this::onConnectClicked);
        sendButton.setOnClickListener(this::onSendClicked);

        hostInput.setText("192.168.1.100");
        portInput.setText("8080");
        messageInput.setText("Hello from Android!");

        updateUI();
    }

    private void setupNode() {
        try {
            RatsNode.setLogLevel(LogLevel.INFO);

            // dataDir keeps the node's identity stable across app restarts.
            node = new RatsNode(new RatsNode.Config()
                    .listenPort(8080)
                    .dataDir(getFilesDir().getAbsolutePath()));

            // Everything below runs while the node is still stopped.
            node.onPeerConnected(peerId -> runOnUiThread(() -> {
                PeerInfo info = node.peerInfo(peerId);
                appendMessage("+ peer " + shortId(peerId)
                        + (info != null ? " over " + info.transport() : ""));
                updateUI();
            }));

            node.onPeerDisconnected((peerId, reason) -> runOnUiThread(() -> {
                appendMessage("- peer " + shortId(peerId) + " (" + reason + ")");
                if (reason == CloseReason.SLOW_CONSUMER) {
                    appendMessage("  we were sending faster than the link could carry");
                }
                updateUI();
            }));

            node.onDialFailed(address -> runOnUiThread(() ->
                    appendMessage("could not reach " + address)));

            node.on(CHAT_CHANNEL, (peerId, data) -> {
                String message = new String(data, StandardCharsets.UTF_8);
                runOnUiThread(() -> appendMessage(shortId(peerId) + ": " + message));
            });

            node.enableMdns();          // find peers on the same Wi-Fi
            node.enablePeerExchange();  // and the peers they know

            appendMessage("librats " + RatsNode.version() + " ready");
        } catch (RatsException e) {
            Log.e(TAG, "Failed to create the node", e);
            appendMessage("error: " + e.getMessage());
        }
    }

    private void onStartClicked(View view) {
        if (node == null) return;
        try {
            acquireMulticastLock();
            node.start();
            appendMessage("started on port " + node.listenPort() + " " + node.transports());
            appendMessage("our peer id: " + node.localId());
            updateUI();
        } catch (RatsException e) {
            Log.e(TAG, "Error starting the node", e);
            appendMessage("error: " + e.getMessage());
        }
    }

    /** Most devices drop multicast, and with it mDNS, unless a MulticastLock is held. */
    private void acquireMulticastLock() {
        if (multicastLock != null) return;
        WifiManager wifi = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifi == null) return;
        multicastLock = wifi.createMulticastLock("librats-mdns");
        multicastLock.setReferenceCounted(false);
        multicastLock.acquire();
    }

    private void onConnectClicked(View view) {
        if (node == null) return;

        String host = hostInput.getText().toString().trim();
        String portStr = portInput.getText().toString().trim();
        if (host.isEmpty() || portStr.isEmpty()) {
            Toast.makeText(this, "Enter a host and port", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            node.connect(host, Integer.parseInt(portStr));
            appendMessage("dialing " + host + ":" + portStr + "…");
        } catch (NumberFormatException e) {
            Toast.makeText(this, "Invalid port number", Toast.LENGTH_SHORT).show();
        } catch (RatsException e) {
            Log.e(TAG, "Error dialing", e);
            appendMessage("error: " + e.getMessage());
        }
    }

    private void onSendClicked(View view) {
        if (node == null) return;

        String message = messageInput.getText().toString().trim();
        if (message.isEmpty()) {
            Toast.makeText(this, "Enter a message", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            node.broadcast(CHAT_CHANNEL, message.getBytes(StandardCharsets.UTF_8));
            appendMessage("me: " + message);
            messageInput.setText("");
        } catch (RatsException e) {
            Log.e(TAG, "Error sending", e);
            appendMessage("error: " + e.getMessage());
        }
    }

    private static String shortId(String peerId) {
        return peerId.length() > 12 ? peerId.substring(0, 12) + "…" : peerId;
    }

    private void appendMessage(String message) {
        Log.d(TAG, message);
        messagesText.append(message + "\n");

        messagesText.post(() -> {
            if (messagesText.getLayout() == null) return;
            int scrollAmount = messagesText.getLayout().getLineTop(messagesText.getLineCount())
                              - messagesText.getHeight();
            messagesText.scrollTo(0, Math.max(scrollAmount, 0));
        });
    }

    private void updateUI() {
        if (node == null) {
            statusText.setText("Status: not initialized");
            startButton.setEnabled(false);
            connectButton.setEnabled(false);
            sendButton.setEnabled(false);
            return;
        }

        int peerCount = node.peerCount();
        statusText.setText("Status: " + peerCount + " peers connected");
        startButton.setEnabled(true);
        connectButton.setEnabled(true);
        sendButton.setEnabled(peerCount > 0);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (node != null) {
            node.close();   // stops the node and frees it
            node = null;
        }
        if (multicastLock != null) {
            multicastLock.release();
            multicastLock = null;
        }
    }
}
