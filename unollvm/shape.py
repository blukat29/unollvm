import angr


def block_contains(outer, inner):
    a = outer.addr
    b = outer.addr + outer.size
    x = inner.addr
    y = inner.addr + inner.size
    return a <= x and y <= b

class ShapeAnalysis:

    def __init__(self, cfg, func_addr):
        # Inputs
        self.cfg = cfg
        self.func_addr = func_addr
        self.func = self.cfg.functions[self.func_addr]
        self.prolog = self.func.get_node(self.func_addr)
        # Results
        self.is_ollvm_shape = None
        self.dispatcher_addr = None
        self.collector_addr = None
        self.leaf_addrs = []

    def is_collector(self, block_addr):
        successors = self.func.get_node(block_addr).successors()

        # Collector ends with an unconditional branch.
        if len(successors) != 1:
            return False
        successor = successors[0]

        # Collector is a basic block, not a function.
        if not isinstance(successor, angr.knowledge.codenode.BlockNode):
            return False

        # Collector jumps to the dispatcher.
        return block_contains(self.prolog, successor)

    def analyze(self):

        # Find exactly one collector.
        collector_addrs = filter(self.is_collector, self.func.block_addrs)
        if len(collector_addrs) != 1:
            self.is_ollvm_shape = False
            return
        else:
            collector_addr = collector_addrs[0]

        # Dispatcher is the jump target of the collector.
        collector = self.func.get_node(collector_addr)
        dispatcher_addr = collector.successors()[0].addr

        # Leaf nodes are nodes without out edges.
        out_degree = self.func.graph.out_degree()
        is_leaf = lambda addr: out_degree[self.func.get_node(addr)] == 0
        leaf_addrs = filter(is_leaf, self.func.block_addrs)

        self.is_ollvm_shape = True
        self.collector_addr = collector_addr
        self.dispatcher_addr = dispatcher_addr
        self.leaf_addrs = leaf_addrs

    def __str__(self):
        s = 'Shape analysis for function 0x{:x}\n'.format(self.func_addr)
        s += '  is_ollvm_shape = {}\n'.format(self.is_ollvm_shape)
        if self.is_ollvm_shape:
            s += '  collector = 0x{:x}\n'.format(self.collector_addr)
            s += '  dispatcher = 0x{:x}\n'.format(self.dispatcher_addr)
            s += '  leaves = [' + ','.join(map(hex, self.leaf_addrs)) + ']\n'
        return s
