import angr


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
        print("Starting analysis for function {:x}".format(addr))
