import logging
import sys

import angr
import keystone

from .control import Control
from .patch import Patch
from .shape import Shape
from .util import patch_elf

log = logging.getLogger('unollvm')

class Deobfuscator(object):

    def __init__(self, filename, verbose=False, logfile=None):
        self.filename = filename
        self.verbose = verbose
        if self.verbose:
            logging.getLogger('unollvm').setLevel(logging.INFO)
        else:
            logging.getLogger('unollvm').setLevel(logging.WARN)
        if logfile:
            handler = logging.FileHandler(logfile)
            handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))
            log.addHandler(handler)

        load_options = {'auto_load_libs': False}
        self.proj = angr.Project(filename, load_options=load_options)
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        self.cfg_cache = None
        self.patches = {}

    def pie_base(self):
        if self.proj.loader.main_object.pic:
            return self.proj.loader.main_object.mapped_base
        else:
            return 0

    def cfg(self):
        if self.cfg_cache is None:
            log.info('Starting CFG analysis')
            self.cfg_cache = self.proj.analyses.CFGFast(show_progressbar=True)
            log.info('Finished CFG analysis')
        return self.cfg_cache

    def analyze_func(self, func):
        shape = Shape(self.proj, func)
        if not shape.is_ollvm:
            return False
        control = Control(self.proj, shape)
        patch = Patch(self.proj, shape, control, self.ks)
        self.patches.update(patch.patches)
        return True

    def analyze_addr(self, addr):
        func = self.cfg().functions[addr]

        if func.is_syscall:
            log.info('Skipping {} (syscall)'.format(repr(func)))
        elif func.is_plt:
            log.info('Skipping {} (plt)'.format(repr(func)))
        elif func.is_simprocedure:
            log.info('Skipping {} (simprocedure)'.format(repr(func)))
        else:
            log.warn('Patching {}..'.format(repr(func)))
            success = self.analyze_func(func)
            if success:
                log.warn('Done {}'.format(repr(func)))
            else:
                log.warn('Fail {}'.format(repr(func)))

    def analyze_name(self, name):
        symbol = self.proj.loader.main_object.get_symbol(name)
        self.analyze_addr(symbol.linked_addr)

    def analyze_all(self):
        for addr in self.cfg().functions:
            self.analyze_addr(addr)

    def commit(self, output):
        patch_elf(self.filename, output, self.patches, self.pie_base())
