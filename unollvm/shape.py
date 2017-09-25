import angr


class Shape(object):

    def __init__(self, func):
        self.func = func
        self.is_ollvm_shape = False
        self.collector = None
        self.dispatcher = None
        self.leaves = []

    def __repr__(self):
        return ("Shape({})".format(repr(self.func)))
