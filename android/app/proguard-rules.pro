# gomobile runtime and bound API surface (also shipped in the AAR's proguard.txt)
-keep class warpcore.** { *; }
-keep class go.** { *; }
-keepclassmembers class go.** { *; }
-dontwarn java.lang.invoke.**
