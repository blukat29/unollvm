import unollvm
import sys

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "usage: patch_one.py orig_file func [new_file]"
        exit(1)
    print "This program is for debug purpose only."

    orig = sys.argv[1]

    func = sys.argv[2]
    if func.startswith('0x'):
        func = int(func, 16)
        is_addr = True
    else:
        is_addr = False

    if len(sys.argv) >= 4:
        new = sys.argv[3]
    else:
        new = orig + '_patched'

    do = unollvm.Deobfuscator(orig, verbose=True)
    if is_addr:
        do.process_function(addr=func)
        p = do.get_patch(addr=func)
    else:
        do.process_function(name=func)
        p = do.get_patch(name=func)
    unollvm.patch_elf(orig, p, new)
