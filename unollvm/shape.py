import angr

def block_contains(outer, inner):
    a = outer.addr
    b = outer.addr + outer.size
    x = inner.addr
    y = inner.addr + inner.size
    return a <= x and y <= b

class Shape(object):

    def __init__(self, func):
        self.func = func
        self.prolog = self.func.get_node(func.addr)
        self.out_degree = self.func.graph.out_degree()

        self.is_ollvm = False
        self.collector = None
        self.dispatcher = None
        self.exits = []

        self.is_ollvm = self.analyze()

    def is_collector(self, addr):
        ss = self.func.get_node(addr).successors()

        # Ends with an unconditional branch.
        if len(ss) != 1:
            return False
        s = ss[0]

        # Collector is a basic block, not a function.
        if not isinstance(s, angr.codenode.BlockNode):
            return False

        # Collector jumps back into the prolog.
        return block_contains(self.prolog, s)

    def is_exit(self, addr):
        # Nodes without outgoing edges.
        return self.out_degree[self.func.get_node(addr)] == 0

    def try_consolidate_collectors(self, collectors):
        # Sometimes, a body block is directly connected to the collector
        # without a jump instruction.
        if len(collectors) != 2:
            return None
        addr0, addr1 = collectors
        node0 = self.func.get_node(addr0)
        node1 = self.func.get_node(addr1)
        if block_contains(node0, node1):
            return addr1
        elif block_contains(node1, node0):
            return addr0
        else:
            return None

    def analyze(self):
        collectors = filter(self.is_collector, self.func.block_addrs)
        if len(collectors) != 1:
            self.collector = self.try_consolidate_collectors(collectors)
            if self.collector == None:
                return False
        else:
            self.collector = collectors[0]

        # Dispatcher is the jump target of the collector.
        collector_node = self.func.get_node(self.collector)
        self.dispatcher = collector_node.successors()[0].addr

        self.exits = filter(self.is_exit, self.func.block_addrs)
        return True

    def __repr__(self):
        return ("Shape({})".format(repr(self.func)))

    def __str__(self):
        return self.__repr__()

    def dump(self):
        s = 'is_ollvm: {}\n'.format(self.is_ollvm)
        if self.is_ollvm:
            s += 'collector: {:x}\n'.format(self.collector)
            s += 'dispatcher: {:x}\n'.format(self.dispatcher)
            exit_list = ','.join(map(lambda n: '{:x}'.format(n), self.exits))
            s += 'exits: [{}]\n'.format(exit_list)
        return s
