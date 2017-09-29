from pwnlib.elf.elf import ELF
import array

def patch_elf(old, new, patches):
    elf = ELF(old)
    for vaddr, content in patches.iteritems():
        content = str(bytearray(content))
        elf.write(vaddr, content)
    elf.save(new)
