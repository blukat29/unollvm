import angr
import keystone

from .binary import patch_elf
from .control import Control
from .patch import Patch
from .shape import Shape


class Deobfuscator(object):

    def __init__(self, filename):
        load_options = {'auto_load_libs': False}
        self.filename = filename
        self.proj = angr.Project(filename, load_options=load_options)
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        self.cfg_cache = None
        self.patches = {}

    def cfg(self):
        if self.cfg_cache is None:
            self.cfg_cache = self.proj.analyses.CFGFast()
        return self.cfg_cache

    def analyze_addr(self, addr):
        self.analyze_func(addr)

    def analyze_name(self, name):
        symbol = self.proj.loader.main_object.get_symbol(name)
        self.analyze_func(symbol.linked_addr)

    def analyze_func(self, addr):
        func = self.cfg().functions[addr]
        print('Starting analysis for {}'.format(repr(func)))

        shape = Shape(func)
        print(shape.dump())
        if not shape.is_ollvm:
            return

        control = Control(self.proj, shape)
        print(control.dump())

        patch = Patch(self.proj, shape, control, self.ks)
        print(patch.dump())
        self.patches.update(patch.patches)

    def commit(self, output):
        patch_elf(self.filename, output, self.patches)
