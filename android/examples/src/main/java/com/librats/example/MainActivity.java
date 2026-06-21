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

import com.librats.RatsClient;
import com.librats.MessageCallback;

import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "LibRatsExample";
    private static final int PERMISSION_REQUEST_CODE = 1;

    // Application channel used by this demo for plain chat messages.
    private static final String CHAT_CHANNEL = "chat";

    private RatsClient ratsClient;
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
        setupRatsClient();
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

        boolean allGranted = true;
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }

        if (!allGranted) {
            ActivityCompat.requestPermissions(this, permissions, PERMISSION_REQUEST_CODE);
        }
    }

    private void setupRatsClient() {
        try {
            // Process-global logging configuration.
            RatsClient.setLogLevel(RatsClient.LOG_INFO);

            // Create a listening node on port 8080.
            ratsClient = new RatsClient(8080);

            // Register peer + message callbacks BEFORE start().
            ratsClient.setConnectionCallback(peerId -> runOnUiThread(() -> {
                appendMessage("Connected to peer: " + peerId);
                updateUI();
            }));

            ratsClient.setDisconnectCallback(peerId -> runOnUiThread(() -> {
                appendMessage("Disconnected from peer: " + peerId);
                updateUI();
            }));

            ratsClient.on(CHAT_CHANNEL, new MessageCallback() {
                @Override
                public void onMessage(String peerId, byte[] data) {
                    final String message = new String(data, StandardCharsets.UTF_8);
                    runOnUiThread(() -> appendMessage("Message from " + peerId + ": " + message));
                }
            });

            // Optionally enable discovery (must be before start()).
            ratsClient.enableMdns();

            appendMessage("LibRats node created");
            appendMessage("Version: " + RatsClient.getVersionString());

        } catch (Exception e) {
            Log.e(TAG, "Failed to create RatsClient", e);
            appendMessage("Error: " + e.getMessage());
        }
    }

    private void onStartClicked(View view) {
        if (ratsClient == null) return;

        try {
            int result = ratsClient.start();
            if (result == RatsClient.OK) {
                appendMessage("Node started on port " + ratsClient.getListenPort());
                appendMessage("Our peer id: " + ratsClient.getLocalId());
                updateUI();
            } else {
                appendMessage("Failed to start: " + RatsClient.errorString(result));
            }
        } catch (Exception e) {
            Log.e(TAG, "Error starting node", e);
            appendMessage("Error starting node: " + e.getMessage());
        }
    }

    private void onConnectClicked(View view) {
        if (ratsClient == null) return;

        String host = hostInput.getText().toString().trim();
        String portStr = portInput.getText().toString().trim();

        if (host.isEmpty() || portStr.isEmpty()) {
            Toast.makeText(this, "Please enter host and port", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            int port = Integer.parseInt(portStr);
            int result = ratsClient.connect(host, port);
            if (result == RatsClient.OK) {
                appendMessage("Connecting to " + host + ":" + port);
            } else {
                appendMessage("Failed to connect: " + RatsClient.errorString(result));
            }
        } catch (NumberFormatException e) {
            Toast.makeText(this, "Invalid port number", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Log.e(TAG, "Error connecting", e);
            appendMessage("Error connecting: " + e.getMessage());
        }
    }

    private void onSendClicked(View view) {
        if (ratsClient == null) return;

        String message = messageInput.getText().toString().trim();
        if (message.isEmpty()) {
            Toast.makeText(this, "Please enter a message", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            // Broadcast the message on our chat channel to every connected peer.
            byte[] payload = message.getBytes(StandardCharsets.UTF_8);
            int result = ratsClient.broadcast(CHAT_CHANNEL, payload);
            if (result == RatsClient.OK) {
                appendMessage("Sent: " + message);
                messageInput.setText("");
            } else {
                appendMessage("Failed to send: " + RatsClient.errorString(result));
            }
        } catch (Exception e) {
            Log.e(TAG, "Error sending message", e);
            appendMessage("Error sending message: " + e.getMessage());
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
        if (ratsClient == null) {
            statusText.setText("Status: Not initialized");
            startButton.setEnabled(false);
            connectButton.setEnabled(false);
            sendButton.setEnabled(false);
            return;
        }

        try {
            int peerCount = ratsClient.getPeerCount();
            statusText.setText("Status: " + peerCount + " peers connected");

            startButton.setEnabled(true);
            connectButton.setEnabled(true);
            sendButton.setEnabled(peerCount > 0);
        } catch (Exception e) {
            statusText.setText("Status: Error");
            Log.e(TAG, "Error updating UI", e);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (ratsClient != null) {
            try {
                ratsClient.stop();
                ratsClient.destroy();
            } catch (Exception e) {
                Log.e(TAG, "Error destroying client", e);
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            if (!allGranted) {
                Toast.makeText(this, "Network permissions are required for LibRats", Toast.LENGTH_LONG).show();
            }
        }
    }
}
