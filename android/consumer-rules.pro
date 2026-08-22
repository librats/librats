# Rules applied to apps that consume this library.

# The public API is reached by name from native code and by the app itself.
-keep public class com.librats.** { *; }

# Callback interfaces are invoked from native code via GetMethodID, so their
# method names must survive obfuscation.
-keep interface com.librats.*Callback { *; }

# FileTransferStatus.fromValue(int) is called from native code via
# GetStaticMethodID.
-keep class com.librats.FileTransferStatus {
    public static com.librats.FileTransferStatus fromValue(int);
}
