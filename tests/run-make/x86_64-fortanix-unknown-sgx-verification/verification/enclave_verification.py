# https://docs.angr.io/core-concepts/toplevel

import archinfo
import angr
import claripy
import hooker
import sys
import pyvex

from angr.calling_conventions import SimCCSystemVAMD64

from enclave_state import EnclaveState
from breakpoints import Breakpoints
from layout import Layout

INSTR_LFENCE = b'\x0f\xae\xe8'
INSTR_MFENCE = b'\x0f\xae\xf0'

class EnclaveVerification:
    MAX_STATES = 25
    GS_SEGMENT_SIZE = 0x1000

    def __init__(self, enclave_path):
        self.enclave = enclave_path
        project = angr.Project(enclave_path, load_options={'auto_load_libs': False})

        # Hook and simulate specific instructions that are unknown to angr
        project = hooker.Hooker().setup(project)
        self.project = project
        self.locate_symbols()

    def locate_symbols(self):
        def find_symbol_matching(name):
            symbols = list(filter(lambda s : name in s.name, self.project.loader.symbols))
            if len(symbols) != 1:
                print("Multiple symbols matching\"", name, "\"found:", symbols)
                exit(-1)
            else:
                return symbols[0]

        self.sgx_entry = self.project.loader.find_symbol("sgx_entry").rebased_addr
        self.entry = self.project.loader.find_symbol("entry").rebased_addr
        self.copy_to_userspace = find_symbol_matching("copy_to_userspace").rebased_addr
        self.panic = find_symbol_matching("panicking5panic").rebased_addr
        self.panic_with_hook = find_symbol_matching("panicking20rust_panic_with_hook").rebased_addr
        self.abort_internal = find_symbol_matching("abort_internal").rebased_addr
        self.enclave_size = self.project.loader.find_symbol("ENCLAVE_SIZE").rebased_addr
        self.image_base = self.project.loader.find_symbol("IMAGE_BASE").rebased_addr
        self.string_from_bytebuffer = find_symbol_matching("string_from_bytebuffer").rebased_addr
        self.usercall = self.project.loader.find_symbol("usercall").rebased_addr

        print("Located symbols:")
        print("  sgx_entry:              " + hex(self.sgx_entry))
        print("  entry:                  " + hex(self.entry))
        print("  image_base:             " + hex(self.image_base))
        print("  copy_to_userspace:      " + hex(self.copy_to_userspace))
        print("  panic:                  " + hex(self.panic))
        print("  string_from_bytebuffer: " + hex(self.string_from_bytebuffer))

    def call_state(self, addr, *args, **kwargs):
        arch = archinfo.arch_from_id("amd64")
        state = self.project.factory.call_state(
                addr,
                *args,
                cc=SimCCSystemVAMD64(arch),
                prototype=kwargs["prototype"],
                ret_addr=kwargs["ret_addr"],
                add_options={"SYMBOLIC_WRITE_ADDRESSES", "SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"})
        state.register_plugin('enclave', EnclaveState(self.project))
        state.enclave.init_trace_and_stack()

        # Fake enclave state
        #state.memory.store(self.enclave_size, state.solver.BVV(0x100000, 64))
        #state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))

        return state

    def simulation_manager(self, state):
        sm = self.project.factory.simulation_manager(state)
        self.project, sm = Breakpoints().setup(self.project, sm, Layout())
        return sm

    def print_states(states, name):
        print("=[", len(states), name, " states ]=")
        for idx_state in range(0, len(states)):
            state = states[idx_state]
            print("[", name, "state ", idx_state + 1, "/", len(states), "]")
            state.enclave.print_state()
            state.enclave.print_call_stack()
            state.enclave.print_trace()
            print("")

    def print_errored_states(records):
        print("=[", len(records), "errored states ]=")
        for idx_state in range(0, len(records)):
            state = records[idx_state].state
            print("[errored state ", idx_state + 1, "/", len(records), "]")
            print("Error: ", records[idx_state].error)
            print("Regs:")
            print(" - %rax = ", state.regs.rax)
            print(" - %rbx = ", state.regs.rbx)
            print(" - %rcx = ", state.regs.rcx, " (arg3)")
            print(" - %rdx = ", state.regs.rdx, " (arg2)")
            print(" - %rsi = ", state.regs.rsi, " (arg1)")
            print(" - %rdi = ", state.regs.rdi, " (arg0)")
            print(" - %r8  = ", state.regs.r8,  " (arg4)")
            print(" - %r9  = ", state.regs.r9,  " (arg5)")
            print(" - %r10 = ", state.regs.r10)
            print(" - %r11 = ", state.regs.r11)
            print(" - %r12 = ", state.regs.r12)
            print(" - %r13 = ", state.regs.r13)
            print(" - %r14 = ", state.regs.r14)
            print(" - %r15 = ", state.regs.r15)
            print(" - %rbp = ", state.regs.rbp)
            print(" - %rsp = ", state.regs.rsp)
            print(" - %rip = ", state.regs.rip)
            #print(" - %d   = ", state.regs.dflag)
            #print(" - %e   = ", state.regs.eflags)
            #print(" - %r   = ", state.regs.get("rflags"))
            print("")

    def process_result(sm):
        if len(sm.found) == EnclaveVerification.MAX_STATES:
            print("Error: Maximum number of states reached:", EnclaveVerification.MAX_STATES)
            return False
        elif len(sm.errored) != 0:
            print("Error: Some states reached an error")
            EnclaveVerification.print_states(sm.found, "Found")
            EnclaveVerification.print_errored_states(sm.errored)
            return False
        elif len(sm.unconstrained) != 0:
            print("Error: Some states reached an unconstrained state")
            EnclaveVerification.print_states(sm.found, "Found")
            EnclaveVerification.print_errored_states(sm.errored)
            return False
        else:
            EnclaveVerification.print_states(sm.found, "Found")
            EnclaveVerification.print_errored_states(sm.errored)
            return True

