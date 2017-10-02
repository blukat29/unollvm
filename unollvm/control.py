import logging
import operator
import re

import angr
import claripy

log = logging.getLogger('unollvm')

class Control(object):

    def __init__(self, proj, shape):
        self.proj = proj
        self.shape = shape
        self.swvar_addr = None
        self.swvar_sym = None
        self.swmap = dict()

        self.success = False
        self.success = self.analyze()

    def default_bp(self):
        return 0x7ffccc008000

    def swvar_name(self):
        return 'swVar'

    def swvar_offset(self):
        return self.swvar_addr - self.default_bp()

    def find_swvar(self, state):
        # Dispatcher node ends with a conditional branch.
        succ = state.step()
        succ = list(succ.successors)
        if len(succ) != 2 or state.history.jumpkind != 'Ijk_Boring':
            return False

        # Extract the variables involved in the branch condition.
        cond = succ[0].guards
        var_names = reduce(operator.or_,
                map(operator.attrgetter('variables'), cond),
                frozenset())

        # We assume that the switch variable (swVar) is bound to
        # a stack local variable. Then there should be only one
        # memory variable, in the stack area.
        if len(var_names) != 1:
            return False
        name = list(var_names)[0]
        if not name.startswith('mem_'):
            return False

        # Remember the location of the swVar.
        match = re.match('mem_([0-9a-fA-F]+).*', name)
        self.swvar_addr = int(match.group(1), 16)
        return True

    def is_swval_constant(self, state):
        '''
        Checks if the form of the guard condition is simple comparison
        with a constant value.
        '''
        guards = list(state.guards)
        # Assume the last guard condition alone can determine the switch value.
        guards = guards[-1:]
        ast = claripy.simplify(reduce(claripy.And, guards, claripy.true))
        if ast.op == '__eq__':
            x, y = ast.args
            if x.op == 'BVV':
                return y.op == 'BVS' and y.args[0].startswith(self.swvar_name())
            elif y.op == 'BVV':
                return x.op == 'BVS' and x.args[0].startswith(self.swvar_name())
        return False

    def is_bottom(self, state):
        if state.addr == self.shape.collector:
            return True
        if state.addr in self.shape.exits:
            return True
        return False

    def explore(self, state):
        '''
        Explore the CFG from the dispatcher node.
        An exploration ends when the guard condition dictates that the
        switch variable must be equal to a constant value. That is, the
        search continues until we find all body blocks and the associated
        switch values.
        '''
        # Stop if we can determine the switch value that leads to current node.
        if self.is_swval_constant(state):
            value = state.se.eval(self.swvar_sym)
            log.info('    {:x} -> {:x}'.format(value, state.addr))
            return dict({value: state.addr})

        # Otherwise keep exploring the successors
        succ = state.step()
        succ = list(succ.successors)

        # Stop exploring at a dead-end.
        if len(succ) == 1 and self.is_bottom(succ[0]):
            return dict()
        if len(succ) == 0:
            return dict()

        # Explore all successor nodes
        maps = dict()
        for s in succ:
            m = self.explore(s)
            maps.update(m)
        return maps


    def analyze(self):
        state = self.proj.factory.blank_state(addr=self.shape.dispatcher)
        state.regs.bp = self.default_bp()

        if not self.find_swvar(state):
            return False
        log.info('  swith variable at {:x} (bp {:x})'.format(
            self.swvar_addr, self.swvar_offset()))

        self.swvar_sym = claripy.BVS(self.swvar_name(), 32)
        state.memory.store(self.swvar_addr, self.swvar_sym.reversed)
        self.swmap = self.explore(state)
        return True

    def __repr__(self):
        return 'Control({}, {})'.format(repr(self.proj), repr(self.shape))

    def __str__(self):
        return self.__repr__()
