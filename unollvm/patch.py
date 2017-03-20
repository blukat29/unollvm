import angr
import capstone
import claripy
import keystone
import re

def sym_is_fixed(sym):
    return sym.op == 'BVV'

def sym_get_val(sym):
    assert sym.op == 'BVV'
    return sym.args[0]

def state_get_reg(state, operand):
    assert re.match('(r|e)..?', operand)
    if operand[-1] == 'd':
        return getattr(state.regs, operand[:-1]).chop(32)[1]
    else:
        return getattr(state.regs, operand)

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

    def update_cmov_info(self, info, addr, state):
        insn = self.disas(addr)
        if insn.mnemonic.startswith('cmov'):
            regs = map(str.strip, str(insn.op_str).split(','))
            iff = state_get_reg(state, regs[0])
            ift = state_get_reg(state, regs[1])
            if sym_is_fixed(iff) and sym_is_fixed(ift):
                iff = sym_get_val(iff)
                ift = sym_get_val(ift)
                # TODO: Could be false positives.
                if iff in self.dispatch.block_map and ift in self.dispatch.block_map:
                    item = {'addr': addr, 'iff': iff, 'ift': ift}
                    info['cmov_info'] = info.get('cmov_info', []) + [item]

    def exec_instrs(self, info, instruction_addrs, state):
        for addr in instruction_addrs:
            self.update_cmov_info(info, addr, state)
            state = self.single_step(state, addr)
        return state

    def exec_block(self, info, addr, state):
        block = self.proj.factory.block(addr)
        jk = block.vex.jumpkind
        if jk == 'Ijk_Boring':
            state = self.exec_instrs(info, block.instruction_addrs, state)
            # Assume we do not meet conditional branch.
            return sym_get_val(state.regs.pc), state
        elif jk == 'Ijk_Call':
            state = self.exec_instrs(info, block.instruction_addrs[:-1], state)
            state.regs.eax = claripy.BVS('retval_from_{:x}'.format(block.instruction_addrs[-1]), 32)
            return addr + block.size, state
        else:
            raise Exception('cannot handle jumpkind "%s"' % jk)

    def analyze_case(self, case):
        print 'Block %8x' % case,

        state = self.orig_state(case)
        orig_sv = self.state_get_sv(state)

        info = {}
        addr = case
        while addr != self.shape.collector_addr and (addr not in self.shape.leaf_addrs):
            addr, state = self.exec_block(info, addr, state)
            curr_sv = self.state_get_sv(state)
            if not (orig_sv == curr_sv).is_true():
                if sym_is_fixed(curr_sv):
                    print 'fixed to %8x' % sym_get_val(curr_sv)
                    return
                elif info['cmov_info']:
                    assert len(info['cmov_info']) == 1
                    ci = info['cmov_info'][0]
                    print 'cmov at %8x for %8x and %8x' % (ci['addr'], ci['ift'], ci['iff'])
                    return
                else:
                    raise Exception('cannot find exit condition')
        print 'no patch'
        return

    def patches(self):
        p = []
        for case in self.dispatch.block_map.values():
            self.analyze_case(case)
        return p
