# JNIAnalyzer

This Ghidra extension contains various scripts that assists in analyzing
Android NDK applications.

# Scripts

### JNIAnalyzer.java

This script uses the [JADX][jadx] decompiler to extract the function signature
of all native methods in an APK file and applies the signature to all
matching fnuctions in the binary.

Running the `JNIAnalyzer.java` extension script will overwrite any function
return types, parameter names and parameter types that was already in place.
If you want the script to skip a specific function, annotate it with
`JNIAnalyzer:IGNORE` in the comment.

Write-up: [Ghidra Plugin: JNIAnalyzer][JNIAnalyzer_blog]

### TraceRegisterNatives.java

This script parses the output of [trace_registernatives][trace_registernatives]
applies the results to the Ghidra project.

Write up coming soon.

### RegisterNatives.java (Experimental)

This script looks for calls to `RegisterNatives` within a function and sets
the `JNINativeMethod` structure type in the appropriate locations within the
binary. Ghidra's P-Code API is used to find references to `RegisterNatives` as
the function is usually resolved at runtime.

This script is currently very much experimental / use at your own risk.

[FindNativeJNIMethods]: https://github.com/Ayrx/FindNativeJNIMethods
[trace_registernatives]: https://github.com/Ayrx/trace_registernatives
[JNIAnalyzer_blog]: https://www.ayrx.me/ghidra-jnianalyzer
[jadx]: https://github.com/skylot/jadx
