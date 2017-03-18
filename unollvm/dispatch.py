import operator
import re

import angr
import claripy


class DispatchAnalysis:

    def __init__(self, proj, shape):
        self.proj = proj
        self.shape = shape
        self.func_addr = self.shape.func_addr

        self.state_var_loc = None
        self.block_map = {}

    def find_state_var(self, s):
        # Symbolically execute the (suspected) dispatcher node.
        p = self.proj.factory.path(s)
        p.step()

        # Dispatcher node ends with a conditional branch.
        if len(p.successors) != 2 or p.jumpkind != 'Ijk_Boring':
            return None

        # cond is composed of multiple frozensets of strings.
        cond = list(p.successors[0].guards)
        variables = reduce(operator.or_,
                map(operator.attrgetter('variables'), cond))

        # The guard condition should be only dependent to
        # a symbolic stack variable.
        if len(variables) != 1:
            return None
        var_name = list(variables)[0]
        if not var_name.startswith('mem_'):
            return None

        loc = int(re.match('mem_([0-9a-fA-F]+).*', var_name).group(1), 16)
        sym = claripy.BVS('state_var', 32)
        return loc, sym

    def path_is_bottom(self, path):
        if path.addr == self.shape.collector_addr:
            return True
        if path.addr in self.shape.leaf_addrs:
            return True
        if len(path.successors) == 0:
            return True
        return False

    def is_state_var_fixed(self, path):
        '''
        Check if a guard condition matches to the form:
            state_var_x_xx == 0x12345678
        '''
        ast = claripy.simplify(
                reduce(claripy.And, path.guards, claripy.true))
        if ast.op == '__eq__':
            x, y = ast.args
            is_state_var = lambda x: x.op == 'BVS' and x.args[0].startswith('state_var')
            is_constant = lambda x: x.op == 'BVV'
            return (is_state_var(x) and is_constant(y)) or \
                   (is_state_var(y) and is_constant(x))

    def explore(self, path, sym):
        path.step()
        if self.is_state_var_fixed(path):
            state_value = path.state.se.any_int(sym)
            return {state_value: path.addr}
        elif self.path_is_bottom(path):
            return {}
        else:
            mapping = {}
            for successor in path.successors:
                mapping.update(self.explore(successor, sym))
            return mapping

    def analyze(self):

        state = self.proj.factory.blank_state(addr=self.shape.dispatcher_addr)
        state.regs.rbp = 0x100000

        loc, sym = self.find_state_var(state.copy())
        state.memory.store(loc, sym.reversed)

        path = self.proj.factory.path(state)
        block_map = self.explore(path, sym)

        self.state_var_loc = loc
        self.block_map = block_map

    def __str__(self):
        s = 'Dispatch analysis for function 0x{:x}\n'.format(self.func_addr)
        for k, v in sorted(self.block_map.items(), key=operator.itemgetter(1)):
            s += '  {:x} -> {:x}\n'.format(k, v)
        return s
