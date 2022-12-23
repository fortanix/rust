# https://docs.angr.io/core-concepts/toplevel

import archinfo
import angr
import claripy
import hooker
import re
import sys
import pyvex

from angr.calling_conventions import SimCCSystemVAMD64

from breakpoints import Breakpoints
from layout import Layout

INSTR_LFENCE = b'\x0f\xae\xe8'
INSTR_MFENCE = b'\x0f\xae\xf0'

class EnclaveVerification:
    MAX_STATES = 25
    GS_SEGMENT_SIZE = 0x1000
    WRITE_VIOLATION = "WRITE_VIOLATION"

    def __init__(self, enclave_path):
        self.enclave = enclave_path
        project = angr.Project(enclave_path, load_options={'auto_load_libs': False})

        # Hook and simulate specific instructions that are unknown to angr
        project = hooker.Hooker().setup(project)
        self.project = project
        self.locate_symbols()

    def find_symbol_matching(self, name):
        exp = re.compile(name)
        symbols = list(filter(lambda s : exp.match(s.name), self.project.loader.symbols))
        if len(symbols) == 0:
            print("No symbols found matching \"", name, "\"")
            exit(-1)
        elif len(symbols) != 1:
            print("Multiple symbols matching\"", name, "\"found:", symbols)
            exit(-1)
        else:
            return symbols[0]

    def locate_symbols(self):
        self.sgx_entry = self.project.loader.find_symbol("sgx_entry").rebased_addr
        self.entry = self.project.loader.find_symbol("entry").rebased_addr
        self.copy_to_userspace = self.find_symbol_matching(".*copy_to_userspace.*").rebased_addr
        self.copy_from_userspace = self.find_symbol_matching(".*copy_from_userspace.*").rebased_addr
        self.panic = self.find_symbol_matching(".*panicking.panic[^_].*").rebased_addr
        self.panic_with_hook = self.find_symbol_matching(".*panicking.*rust_panic_with_hook.*").rebased_addr
        self.abort_internal = self.find_symbol_matching(".*abort_internal.*").rebased_addr
        self.enclave_size = self.project.loader.find_symbol("ENCLAVE_SIZE").rebased_addr
        self.image_base = self.project.loader.find_symbol("IMAGE_BASE").rebased_addr
        self.string_from_bytebuffer = self.find_symbol_matching(".*string_from_bytebuffer.*").rebased_addr
        self.usercall = self.project.loader.find_symbol("usercall").rebased_addr
        self.memcpy = self.project.loader.find_symbol("memcpy").rebased_addr
        self.alloc = self.project.loader.find_symbol("__rust_alloc").rebased_addr
        self.dealloc = self.project.loader.find_symbol("__rust_dealloc").rebased_addr

        print("Located symbols:")
        print("  sgx_entry:              " + hex(self.sgx_entry))
        print("  entry:                  " + hex(self.entry))
        print("  image_base:             " + hex(self.image_base))
        print("  copy_to_userspace:      " + hex(self.copy_to_userspace))
        print("  copy_from_userspace:    " + hex(self.copy_from_userspace))
        print("  panic:                  " + hex(self.panic))
        print("  string_from_bytebuffer: " + hex(self.string_from_bytebuffer))
        print("  memcpy:                 " + hex(self.memcpy))

    def call_state(self, addr, *args, **kwargs):
        arch = archinfo.arch_from_id("amd64")
        state = self.project.factory.call_state(
                addr,
                *args,
                cc=SimCCSystemVAMD64(arch),
                prototype=kwargs["prototype"],
                ret_addr=kwargs["ret_addr"],
                add_options={"SYMBOLIC_WRITE_ADDRESSES", "SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"})

        # Fake enclave state
        #state.memory.store(self.enclave_size, state.solver.BVV(0x100000, 64))
        #state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))

        return state

    def simulation_manager(self, state):
        sm = self.project.factory.simulation_manager(state)
        self.project, sm = Breakpoints().setup(self.project, sm, Layout())
        return sm

    def print_states(self, records, state_name):
        print("=[", len(records), state_name, "states ]=")
        for idx_state in range(0, len(records)):
            state = records[idx_state]
            print("[", state_name, "state ", idx_state + 1, "/", len(records), "]")
            try:
                print("Error: ", records[idx_state].error)
                state = records[idx_state].state
            except:
                ()
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

            # https://docs.angr.io/core-concepts/states#the-callstack-plugin
            print("Callsite (most recent last):")
            for frame in reversed(state.callstack):
                callsite = frame.call_site_addr
                function_addr = frame.func_addr
                function = self.project.loader.find_symbol(function_addr)
                if function is not None:
                    function = function.name
                print("- ", hex(callsite), ": call", function, "@", hex(function_addr))
            print("")

            # https://docs.angr.io/core-concepts/states#the-history-plugin
            print("Basic block history (most recent last):")
            for address in state.history.bbl_addrs:
                symbol = self.project.loader.find_symbol(address)
                if symbol is not None:
                    symbol = symbol.name
                print("-> ", hex(address), "@", symbol)
            print("")
            print("")

    def process_result(self, sm):
        ret = False

        if len(sm.found) == EnclaveVerification.MAX_STATES:
            print("Error: Maximum number of states reached:", EnclaveVerification.MAX_STATES)
        elif len(sm.stashes[self.WRITE_VIOLATION]) != 0:
            print("Error: Some states reached a write violation")
        elif len(sm.errored) != 0:
            print("Error: Some states reached an error")
        elif len(sm.unconstrained) != 0:
            print("Error: Some states reached an unconstrained state")
        else:
            ret = True
        self.print_states(sm.stashes[self.WRITE_VIOLATION], "Write violation")
        self.print_states(sm.found, "Found")
        self.print_states(sm.errored, "Error")
        return ret
