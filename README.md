# unollvm

This repository is no longer maintained.


An Obfuscator-LLVM deobfuscator based on symbolic execution and pattern matching.
Unlike other tools that produce IL or CFG, this project aims to binary patch the binary.
The deobfuscated binaries run without problem and can be subject to dynamic analysis.

Currently only works with small x86-64 binaries obfuscated with cff (control-flow-flattening) pass.
