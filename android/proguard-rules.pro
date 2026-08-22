# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Keep the public LibRats API and native bridge.
-keep public class com.librats.** { *; }

# Native methods are resolved by name from librats_jni.cpp.
-keepclasseswithmembernames class com.librats.RatsNode {
    native <methods>;
}

# Callback interfaces are invoked from native code via GetMethodID (onPeer /
# onMessage / onTopicMessage / onJsonMessage / onFileOffer / onFileProgress /
# onFileComplete), so their method names must survive obfuscation.
-keep interface com.librats.*Callback { *; }

# FileTransferStatus.fromValue(int) is called from native code via
# GetStaticMethodID to build the value handed to FileProgressCallback.
-keep class com.librats.FileTransferStatus {
    public static com.librats.FileTransferStatus fromValue(int);
}