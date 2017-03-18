import angr
import capstone
import claripy
import keystone
import re


def sym_is_const(sym):
    return sym.op == 'BVV'
def sym_const_val(sym):
    val, bits = sym.args
    assert bits == 32
    return val

def insns_to_dict(insns):
    d = {}
    for elem in insns:
        insn = elem.insn
        d[insn.address] = insn
    return d

def state_get_val(state, operand):
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

    def consolidate_block(self, addr):
        '''
        Consolidate basic blocks connected by calls and syscalls.
        Except call and return instructions.
        Returns list of instruction addresses, and instructions.
        '''
        blocks = []
        addrs = []
        insns = {}
        while True:
            block = self.proj.factory.block(addr)
            insns.update(insns_to_dict(block.capstone.insns))
            addr += block.size
            # Exclude branch instruction.
            if block.vex.jumpkind == 'Ijk_Boring':
                addrs += block.instruction_addrs
                break
            elif block.vex.jumpkind == 'Ikj_Ret':
                addrs += block.instruction_addrs[:-1]
                break
            else:
                addrs += block.instruction_addrs[:-1]
        return addrs, insns

    def single_step(self, state, pc):
        state.regs.pc = pc
        path = self.proj.factory.path(state)
        path.step(num_inst=1)
        assert len(path.successors) == 1
        return path.successors[0].state

    def get_cmov_values(self, state, insn):
        if insn.mnemonic[:4] == 'cmov':
            regs = map(str.strip, str(insn.op_str).split(','))
            iftrue = state_get_val(state, regs[1])
            iffalse = state_get_val(state, regs[0])
            if sym_is_const(iftrue) and sym_is_const(iffalse):
                return sym_const_val(iftrue), sym_const_val(iffalse)
            else:
                return None
        else:
            return None

    def make_patch(self, at, code):
        bytes_, _ = self.ks.asm(code, addr=at)
        patch = []
        for ofs, byte in enumerate(bytes_):
            patch.append((at+ofs, byte))
        return patch

    def patch_const_exit(self, at, next_sv):
        target = self.dispatch.block_map[next_sv]
        code = 'jmp 0x%x' % target
        return self.make_patch(at, code)

    def patch_cond_move(self, at, cc, sv_iftrue, sv_iffalse):
        target_iftrue = self.dispatch.block_map[sv_iftrue]
        target_iffalse = self.dispatch.block_map[sv_iffalse]
        code = 'j%s 0x%x;' % (cc, target_iftrue)
        code += 'jmp 0x%x' % target_iffalse
        return self.make_patch(at, code)

    def patch_beginning(self):
        addr = self.shape.func.addr

        state = self.proj.factory.blank_state(addr=addr)
        state.regs.rsp = 0x100008
        orig_sv = state.memory.load(self.dispatch.state_var_loc, 4).reversed

        addrs, insns = self.consolidate_block(addr)
        for addr in addrs:
            state = self.single_step(state, addr)

            # Check if state variable is changed.
            curr_sv = state.memory.load(self.dispatch.state_var_loc, 4).reversed
            if not (orig_sv == curr_sv).is_true():
                assert sym_is_const(curr_sv)
                return self.patch_const_exit(addrs[-1], sym_const_val(curr_sv))

    def patch_block(self, addr):
        print '%8x:' % addr,
        state = self.proj.factory.blank_state(addr=addr)
        state.regs.rbp = 0x100000
        orig_sv = state.memory.load(self.dispatch.state_var_loc, 4).reversed

        addrs, insns = self.consolidate_block(addr)
        last_cmov_vals = None
        last_cmov_addr = None

        if addr == 0x4046b9:
            print
            return self.patch_const_exit(addrs[-1], 0x10dcdb4c)
        for addr in addrs:

            cmov_values = self.get_cmov_values(state, insns[addr])
            if cmov_values:
                last_cmov_vals = cmov_values
                last_cmov_addr = addr

            state = self.single_step(state, addr)

            # Check if state variable is changed.
            curr_sv = state.memory.load(self.dispatch.state_var_loc, 4).reversed
            if not (orig_sv == curr_sv).is_true():
                print '%8x' % addr,
                if sym_is_const(curr_sv):
                    print 'fixed %8x' % sym_const_val(curr_sv)
                    return self.patch_const_exit(addrs[-1], sym_const_val(curr_sv))
                elif last_cmov_addr:
                    print 'cond  %8x %8x' % last_cmov_vals
                    return self.patch_cond_move(last_cmov_addr,
                                                insns[last_cmov_addr].mnemonic[4:],
                                                last_cmov_vals[0],
                                                last_cmov_vals[1])
                else:
                    raise Exception('cannot patch block %x' % addr)
        print 'Cannot handle this block.'
        return []

    def patches(self):
        p = []
        p += self.patch_beginning()
        for addr in self.dispatch.block_map.values():
            p += self.patch_block(addr)
        return p
