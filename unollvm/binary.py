from elftools.elf.elffile import ELFFile


def elf_segments(filename):
    segments = []
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        for i in range(elf.num_segments()):
            h = elf.get_segment(i).header
            if h['p_type'] == 'PT_LOAD':
                start = h['p_vaddr']
                end = start + h['p_filesz']
                offset = h['p_offset']
                segments.append((start, end, offset))
    return segments

def vaddr_to_offset(segments, vaddr):
    for start, end, offset in segments:
        if start <= vaddr and vaddr < end:
            return offset + (vaddr - start)
    raise ValueError('cannot find file offset for vaddr 0x%x' % vaddr)

def patch_elf(filename, patches, outfile=None):
    outfile = outfile or (filename + '_patched')
    segments = elf_segments(filename)

    with open(filename, 'rb') as f:
        patched = bytearray(f.read())

    for addr, byte in patches:
        offset = vaddr_to_offset(segments, addr)
        patched[offset] = byte

    with open(outfile, 'wb') as f:
        f.write(patched)
