import angr
import capstone
import claripy
import keystone
import re

def sym_get_val(sym):
    assert sym.op == 'BVV'
    return sym.args[0]

class PatchAnalysis:

    def __init__(self, proj, shape, dispatch):
        self.proj = proj
        self.shape = shape
        self.dispatch = dispatch
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        self.disas_cache = {}

    def disas(self, addr):
        if addr in self.disas_cache:
            return self.disas_cache[addr]
        else:
            block = self.proj.factory.block(addr)
            insns = block.capstone.insns
            for item in insns:
                insn = item.insn
                self.disas_cache[insn.address] = insn
            return self.disas_cache[addr]

    def orig_state(self, case):
        state = self.proj.factory.blank_state(addr=case)
        state.regs.rbp = 0x100000
        return state

    def state_get_sv(self, state):
        return state.memory.load(self.dispatch.state_var_loc, 4).reversed

    def single_step(self, state, pc):
        state.regs.pc = pc
        path = self.proj.factory.path(state)
        path.step(num_inst=1)
        assert len(path.successors) == 1
        return path.successors[0].state

    def exec_instrs(self, instruction_addrs, state):
        for addr in instruction_addrs:
            print self.disas(addr)
            state = self.single_step(state, addr)
        return state

    def exec_block(self, addr, state):
        block = self.proj.factory.block(addr)
        jk = block.vex.jumpkind
        if jk == 'Ijk_Boring':
            state = self.exec_instrs(block.instruction_addrs, state)
            # Assume we do not meet conditional branch.
            return sym_get_val(state.regs.pc), state
        elif jk == 'Ijk_Call':
            state = self.exec_instrs(block.instruction_addrs[:-1], state)
            return addr + block.size, state
        else:
            raise Exception('cannot handle jumpkind "%s"' % jk)

    def analyze_case(self, case):
        print '------ %8x' % case

        state = self.orig_state(case)
        orig_sv = self.state_get_sv(state)

        addr = case
        while addr != self.shape.collector_addr and (addr not in self.shape.leaf_addrs):
            addr, state = self.exec_block(addr, state)
            print hex(addr)

    def patches(self):
        p = []
        for case in self.dispatch.block_map.values():
            self.analyze_case(case)
        return p
