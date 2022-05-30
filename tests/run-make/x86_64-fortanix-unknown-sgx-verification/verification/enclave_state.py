""" Guardian
    Copyright (C) 2021  The Blockhouse Technology Limited (TBTL)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>."""

import angr
from copy import deepcopy

class TraceElement:
    def __init__(self, project, addr):
        self.address = addr
        self.symbol = None
        symbol = project.loader.find_symbol(self.address)
        if symbol is not None:
            self.symbol = symbol.name


class EnclaveState(angr.SimStatePlugin):
    def __init__(self,
            proj=None,
            call_stack=None,
            jump_trace=None):
        super().__init__()
        self.jump_trace = [] #None
        self.call_stack = [] #None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        jump_trace=self.jump_trace.copy() if self.jump_trace is not None else None
        call_stack=self.call_stack.copy() if self.call_stack is not None else None
        return EnclaveState(
            jump_trace=jump_trace,
            call_stack=call_stack)
            

    def init_trace_and_stack(self):
        self.jump_trace = [TraceElement(self.state.project, self.state.addr)]
        self.call_stack = [TraceElement(self.state.project, self.state.addr)]

    def print_trace(self, only_elements_with_symbol=True):
        print("Trace:")
        for te in self.jump_trace:
            if not only_elements_with_symbol or te.symbol is not None:
                print(" - {} @ {}".format(hex(te.address), te.symbol))
            else:
                print(" - <unknown>")
        print("End of callstack")

    def print_call_stack(self, only_elements_with_symbol=True):
        print("Callstack:")
        for te in self.call_stack:
            # if not only_elements_with_symbol or te.symbol is not None:
            print(" - {} @ {}".format(hex(te.address), te.symbol))
        print("End of trace")

    def print_state(self):
        print("Regs:")
        print(" - %rax = ", self.state.regs.rax, " (ret)")
        print(" - %rbx = ", self.state.regs.rbx)
        print(" - %rcx = ", self.state.regs.rcx, " (arg3)")
        print(" - %rdx = ", self.state.regs.rdx, " (arg2)")
        print(" - %rsi = ", self.state.regs.rsi, " (arg1)")
        print(" - %rdi = ", self.state.regs.rdi, " (arg0)")
        print(" - %r8  = ", self.state.regs.r8,  " (arg4)")
        print(" - %r9  = ", self.state.regs.r9,  " (arg5)")
        print(" - %r10 = ", self.state.regs.r10)
        print(" - %r11 = ", self.state.regs.r11)
        print(" - %r12 = ", self.state.regs.r12)
        print(" - %r13 = ", self.state.regs.r13)
        print(" - %r14 = ", self.state.regs.r14)
        print(" - %r15 = ", self.state.regs.r15)
        print(" - %rbp = ", self.state.regs.rbp)
        print(" - %rsp = ", self.state.regs.rsp)
        print(" - %rip = ", self.state.regs.rip)
        print(" - %d = ", self.state.regs.dflag)
        print(" - %e = ", self.state.regs.eflags)
        print(" - %r = ", self.state.regs.get("rflags"))
        #print(" - other = ", self.state.regs)
