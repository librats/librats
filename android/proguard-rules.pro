# Rules for minifying this library module itself. Apps that depend on it get
# consumer-rules.pro, which carries the same keeps.

# librats_jni.cpp reaches com.librats by name: the native methods of RatsNode,
# the fields of RatsNode$Config, the constructors of PathStats, PeerInfo and
# FileTransferProgress, CloseReason.fromValue, and the method of every
# *Callback interface. Keeping the whole (small) package keeps all of them.
-keep class com.librats.** { *; }
