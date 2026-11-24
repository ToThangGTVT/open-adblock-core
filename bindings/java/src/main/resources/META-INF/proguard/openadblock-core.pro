# Open AdBlock core: JNI resolves natives and callback methods by name.
-keepclasseswithmembernames,includedescriptorclasses class io.github.tothanggtvt.openadblock.core.NativeBindings {
    native <methods>;
}
-keep interface io.github.tothanggtvt.openadblock.core.SocketProtector { *; }
-keepclassmembers class * implements io.github.tothanggtvt.openadblock.core.SocketProtector {
    public boolean protect(int);
    public int connectionOwner(int, java.lang.String, int, java.lang.String, int);
}
-keep interface io.github.tothanggtvt.openadblock.core.EngineEventListener { *; }
-keepclassmembers class * implements io.github.tothanggtvt.openadblock.core.EngineEventListener {
    public void onEvents(java.lang.String);
}
-keep interface io.github.tothanggtvt.openadblock.core.CertificateSigner { *; }
-keepclassmembers class * implements io.github.tothanggtvt.openadblock.core.CertificateSigner {
    public byte[] sign(byte[]);
}
-keep interface io.github.tothanggtvt.openadblock.core.PacketSink { *; }
-keepclassmembers class * implements io.github.tothanggtvt.openadblock.core.PacketSink {
    public void onPacket(byte[]);
}
