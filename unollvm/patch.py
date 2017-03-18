import angr
import capstone
import claripy
import keystone
import re

class PatchAnalysis:

    def __init__(self, proj, shape, dispatch):
        self.proj = proj
        self.shape = shape
        self.dispatch = dispatch
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    def patches(self):
        p = []
        for case in self.dispatch.block_map.values():
            break
        return p
