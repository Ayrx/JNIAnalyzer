# JNIAnalyzer

This Ghidra extension parses the output of
[FindNativeJNIMethods][FindNativeJNIMethods] and applies the function signature
to all matching functions in the binary.

Running the `JNIAnalyzer.java` extension script will overwrite any function
return types, parameter names and parameter types that was already in place.
If you want the script to skip a specific function, annotate it with
`JNIAnalyzer:IGNORE` in the comment.

Write-up: [Ghidra Plugin: JNIAnalyzer][JNIAnalyzer]

## Experimental Scripts

### RegisterNatives.java

This script looks for calls to `RegisterNatives` within a function and sets
the `JNINativeMethod` structure type in the appropriate locations within the
binary. Ghidra's P-Code API is used to find references to `RegisterNatives` as
the function is usually resolved at runtime.

This script is currently very much experimental / use at your own risk.

[FindNativeJNIMethods]: https://github.com/Ayrx/FindNativeJNIMethods
[JNIAnalyzer_blog]: https://www.ayrx.me/ghidra-jnianalyzer
