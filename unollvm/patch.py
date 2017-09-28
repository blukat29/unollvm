import angr

def sym_val(sym):
    assert sym.op == 'BVV'
    return sym.args[0]

class Patch(object):

    def __init__(self, proj, shape, control, ks):
        self.proj = proj
        self.shape = shape
        self.control = control
        self.ks = ks
        self.patches = dict()
        self.init_swval = None

        self.analyze()

    def get_swvar(self, state):
        # Assume state variable is 4-byte integer type.
        return state.memory.load(self.control.swvar_addr, 4).reversed

    def exec_insns(self, state, insn_addrs, on_insn):
        for addr in insn_addrs:
            state.regs.pc = addr
            succ = state.step(num_inst=1)
            assert len(succ.successors) == 1
            state = succ[0]
            if on_insn:
                if not on_insn(state, addr):
                    break
        return state

    def exec_block(self, state, addr, on_insn=None):
        '''
        Execute a basic block, but ignore any call instruction,
        because we want to keep the analysis inside function.

        on_insn: function (state, addr) -> bool
            the execution stops whtn on_insn returns a falsey.

        returns: (state, addr)
        '''
        block = self.proj.factory.block(addr)
        jk = block.vex.jumpkind
        insn_addrs = block.instruction_addrs
        if jk == 'Ijk_Boring':
            # Assume we do not meet conditional branch.
            # We will only execute the prologue blocks and switch-case bodies,
            # which do not contain conditional branch instructions in a
            # control-flow-flattening obfuscated program.
            state = self.exec_insns(state, insn_addrs, on_insn)
            return state, sym_val(state.regs.pc)
        else:
            raise Exception('Cannot handle jumpkind {}'.format(jk))
        return

    def analyze_dispatcher(self):
        '''
        Execute prologue blocks until initial switch value is determined.
        '''
        addr = self.shape.func.addr
        state = self.proj.factory.blank_state(addr=addr)
        # Assume that the function prologue starts with "push bp; mov bp, sp"
        state.regs.sp = self.control.default_bp() + self.proj.arch.bytes
        orig_sv = self.get_swvar(state)

        # Run until we know initial concrete value of the switch variable.
        def check_swvar(state, addr):
            var = self.get_swvar(state)
            if var.op == 'BVV':
                self.init_swval = sym_val(var)
                return False
            return True

        while addr != self.shape.collector and (addr not in self.shape.exits):
            state, addr = self.exec_block(state, addr, check_swvar)
            if self.init_swval is not None:
                break

    def analyze(self):
        self.analyze_dispatcher()
        return False

    def __repr__(self):
        return "Patch({}, {}, {})".format(self.proj, self.shape, self.control)

    def __str__(self):
        return self.__repr__()

    def dump(self):
        s = ''
        s += 'Initial switch variable: {:x}'.format(self.init_swval)
        return s
