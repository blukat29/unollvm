import sys

import angr
import keystone

from .binary import patch_elf
from .control import Control
from .patch import Patch
from .shape import Shape


class Deobfuscator(object):

    def __init__(self, filename, verbose=False, logfile=sys.stdout):
        self.filename = filename
        self.verbose = verbose
        self.logfile = logfile

        load_options = {'auto_load_libs': False}
        self.proj = angr.Project(filename, load_options=load_options)
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        self.cfg_cache = None
        self.patches = {}

    def log(self, message):
        if self.verbose:
            self.logfile.write(message)
            self.logfile.write('\n')

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
        self.log('Analysis for {}'.format(repr(func)))

        shape = Shape(func)
        self.log(shape.dump())
        if not shape.is_ollvm:
            return

        control = Control(self.proj, shape)
        self.log(control.dump())

        patch = Patch(self.proj, shape, control, self.ks)
        self.log(patch.dump())
        self.patches.update(patch.patches)

    def analyze_all(self):
        for addr in self.cfg().functions:
            self.analyze_func(addr)

    def commit(self, output):
        patch_elf(self.filename, output, self.patches)
