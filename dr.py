import unollvm

do = unollvm.Deobfuscator('/home/blu/bins/simple', verbose=True)
do.process_function(name='main')
p = do.get_patch(name='main')
unollvm.patch_elf('/home/blu/bins/simple', p)


