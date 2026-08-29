package com.librats.example;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.librats.LogLevel;
import com.librats.RatsException;
import com.librats.RatsNode;

import java.nio.charset.StandardCharsets;

/**
 * Minimal librats chat: start a node, dial a peer, broadcast on a channel.
 *
 * <p>Note the ordering — every callback and every {@code enable*} happens while
 * the node is still stopped, and callbacks arrive on a reactor thread, so each
 * one hops to the UI thread before touching a view.</p>
 */
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "LibRatsExample";
    private static final int PERMISSION_REQUEST_CODE = 1;

    /** Application channel this demo uses for chat messages. */
    private static final String CHAT_CHANNEL = "chat";

    private RatsNode node;
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
        checkPermissions();
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

    private void checkPermissions() {
        String[] permissions = {
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_MULTICAST_STATE
        };

        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, permissions, PERMISSION_REQUEST_CODE);
                return;
            }
        }
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
                appendMessage("+ peer " + peerId);
                updateUI();
            }));

            node.onPeerDisconnected((peerId, reason) -> runOnUiThread(() -> {
                appendMessage("- peer " + peerId + " (" + reason + ")");
                updateUI();
            }));

            node.on(CHAT_CHANNEL, (peerId, data) -> {
                String message = new String(data, StandardCharsets.UTF_8);
                runOnUiThread(() -> appendMessage(peerId.substring(0, 16) + "…: " + message));
            });

            node.enableMdns();   // find peers on the same Wi-Fi

            appendMessage("librats " + RatsNode.version() + " ready");
        } catch (RatsException e) {
            Log.e(TAG, "Failed to create the node", e);
            appendMessage("error: " + e.getMessage());
        }
    }

    private void onStartClicked(View view) {
        if (node == null) return;
        try {
            node.start();
            appendMessage("started on port " + node.listenPort() + " (" + node.transports() + ")");
            appendMessage("our peer id: " + node.localId());
            updateUI();
        } catch (RatsException e) {
            Log.e(TAG, "Error starting the node", e);
            appendMessage("error: " + e.getMessage());
        }
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

    private void appendMessage(String message) {
        Log.d(TAG, message);
        messagesText.append(message + "\n");

        messagesText.post(() -> {
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

        try {
            long peerCount = node.peerCount();
            statusText.setText("Status: " + peerCount + " peers connected");
            startButton.setEnabled(true);
            connectButton.setEnabled(true);
            sendButton.setEnabled(peerCount > 0);
        } catch (RatsException e) {
            statusText.setText("Status: error");
            Log.e(TAG, "Error updating the UI", e);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (node != null) {
            node.close();   // stops the node and releases the native resources
            node = null;
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != PERMISSION_REQUEST_CODE) return;
        for (int result : grantResults) {
            if (result != PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Network permissions are required for librats",
                        Toast.LENGTH_LONG).show();
                return;
            }
        }
    }
}
