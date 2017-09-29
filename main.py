import unollvm
import sys

filename = sys.argv[1]
addr = int(sys.argv[2], 16)
output = sys.argv[3]
do = unollvm.Deobfuscator(filename)
do.analyze_func(addr)
do.commit(output)
