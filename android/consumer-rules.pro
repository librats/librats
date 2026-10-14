# Applied to apps that depend on librats.

# librats_jni.cpp reaches com.librats by name: the native methods of RatsNode,
# the fields of RatsNode$Config, the constructors of PathStats, PeerInfo and
# FileTransferProgress, CloseReason.fromValue, and the method of every
# *Callback interface. A renamed or stripped one fails JNI_OnLoad (or a call),
# so the whole package is kept.
-keep class com.librats.** { *; }
