# Classes, fields and methods accessed from native code (JNI) by name must not be renamed or removed.
-keep class io.github.cinnamon415.packetwall.engine.** { *; }

# OkHttp ships its own consumer rules; silence optional platform deps
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# WorkManager uses Room; R8 full mode strips the generated database constructor
-keep class * extends androidx.room.RoomDatabase { <init>(); }
