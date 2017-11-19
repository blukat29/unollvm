from pwnlib.elf.elf import ELF
import array

def patch_elf(old, new, patches, pie_base=0):
    elf = ELF(old)
    for vaddr, content in patches.iteritems():
        content = str(bytearray(content))
        elf.write(int(vaddr) - pie_base, content)
    elf.save(new)
