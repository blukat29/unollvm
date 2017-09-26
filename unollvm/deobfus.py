import angr
from .shape import Shape
from .control import Control


class Deobfuscator(object):

    def __init__(self, filename):
        load_options = {'auto_load_libs': False}
        self.proj = angr.Project(filename, load_options=load_options)
        self.cfg_cache = None
        self.patches = {}

    def cfg(self):
        if self.cfg_cache is None:
            self.cfg_cache = self.proj.analyses.CFGFast()
        return self.cfg_cache

    def analyze_func(self, addr):
        func = self.cfg().functions[addr]
        print('Starting analysis for {}'.format(repr(func)))

        shape = Shape(func)
        print(shape)
        if not shape.is_ollvm:
            return

        control = Control(self.proj, func, shape)
        print(control)

