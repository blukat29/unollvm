import angr

from .dispatch import DispatchAnalysis
from .patch import PatchAnalysis
from .shape import ShapeAnalysis


class Deobfuscator:

    def __init__(self, filename, verbose=False):
        load_options = {'auto_load_libs': False}
        self.proj = angr.Project(filename, load_options=load_options)
        self.cfg = self.proj.analyses.CFGFast()
        self.patches = {}
        self.verbose = verbose

    def get_func_addr(self, addr, name):
        if not addr and not name:
            raise Exception('You must specify function address or name')
        if not addr:
            addr = self.proj.loader.main_bin.get_symbol(name).addr
        return addr

    def process_function(self, addr=None, name=None):
        addr = self.get_func_addr(addr, name)
        if self.verbose:
            print 'Processing function %x' % addr

        shape = ShapeAnalysis(self.cfg, addr)
        shape.analyze()
        if self.verbose:
            print shape

        dispatch = DispatchAnalysis(self.proj, shape)
        dispatch.analyze()
        if self.verbose:
            print dispatch

        patch = PatchAnalysis(self.proj, shape, dispatch)
        patches = patch.patches()
        if self.verbose:
            print
            #print patches
        self.patches[addr] = patches
        return patches

    def get_patch(self, addr=None, name=None):
        addr = self.get_func_addr(addr, name)
        return self.patches[addr]
