import unollvm
import sys

filename = 'example/small.fla'
addr = 0x400480
do = unollvm.Deobfuscator(filename)
do.analyze_func(addr)
