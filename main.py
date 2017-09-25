import unollvm
import sys

filename = sys.argv[1]
addr = int(sys.argv[2], 16)
do = unollvm.Deobfuscator(filename)
do.analyze_func(addr)
