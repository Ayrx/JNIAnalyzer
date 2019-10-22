# JNIAnalyzer

This Ghidra extension parses the output of
[FindNativeJNIMethods][FindNativeJNIMethods] and applies the function signature
to all matching functions in the binary.

Running the `JNIAnalyzer.java` extension script will overwrite any function
return types, parameter names and parameter types that was already in place.
If you want the script to skip a specific function, annotate it with
`JNIAnalyzer:IGNORE` in the comment.

Write-up: [Ghidra Plugin: JNIAnalyzer](https://www.ayrx.me/ghidra-jnianalyzer)

[FindNativeJNIMethods]: https://github.com/Ayrx/FindNativeJNIMethods
