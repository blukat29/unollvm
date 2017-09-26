import angr
import claripy


class Control(object):

    def __init__(self, proj, func, shape):
        self.proj = proj
        self.func = func
        self.shape = shape
        self.analyze()

    def analyze(self):
        state = self.proj.factory.blank_state(addr=self.shape.dispatcher)

