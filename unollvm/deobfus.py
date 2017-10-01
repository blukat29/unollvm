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

    def log(self, message, always=False):
        if self.verbose or always:
            self.logfile.write(message)
            self.logfile.flush()

    def cfg(self):
        if self.cfg_cache is None:
            self.cfg_cache = self.proj.analyses.CFGFast()
        return self.cfg_cache

    def analyze_func(self, func):
        shape = Shape(func)
        self.log(shape.dump())
        if not shape.is_ollvm:
            return False
        self.log('\n')

        control = Control(self.proj, shape)
        self.log(control.dump() + '\n')

        patch = Patch(self.proj, shape, control, self.ks)
        self.log(patch.dump() + '\n')

        self.patches.update(patch.patches)
        return True

    def analyze_addr(self, addr):
        func = self.cfg().functions[addr]
        self.log('\n')
        self.log('Patching {} ...'.format(repr(func)), True)
        self.log('\n')

        if func.is_syscall: self.log(' skip (syscall).\n', True)
        elif func.is_plt: self.log(' skip (plt).\n', True)
        elif func.is_simprocedure: self.log(' skip (simprocedure).\n', True)
        else:
            success = self.analyze_func(func)
            if success: self.log(' done.\n', True)
            else: self.log(' fail.\n', True)

    def analyze_name(self, name):
        symbol = self.proj.loader.main_object.get_symbol(name)
        self.analyze_addr(symbol.linked_addr)

    def analyze_all(self):
        for addr in self.cfg().functions:
            self.analyze_addr(addr)

    def commit(self, output):
        patch_elf(self.filename, output, self.patches)
