# https://docs.angr.io/core-concepts/toplevel

import archinfo
import angr
import claripy
import hooker
import logging
import re
import sys
import pyvex

from angr.calling_conventions import SimCCSystemVAMD64

INSTR_LFENCE = b'\x0f\xae\xe8'
INSTR_MFENCE = b'\x0f\xae\xf0'

class EnclaveVerification:
    MAX_STATES = 25
    GS_SEGMENT_SIZE = 0x1000
    WRITE_VIOLATION = "WRITE_VIOLATION"
    READ_VIOLATION = "READ_VIOLATION"

    def __init__(self, enclave_path, name):
        self.enclave = enclave_path
        self.logger = self.create_logger(name)
        self.logger.info("Load project")
        project = angr.Project(enclave_path, load_options={'auto_load_libs': False})

        # Hook and simulate specific instructions that are unknown to angr
        project = hooker.Hooker().setup(project)
        self.project = project
        self.locate_symbols()

    def create_logger(self, name):
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(name + '.log')
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        return logger

    def find_symbol_matching(self, name):
        exp = re.compile(name)
        symbols = list(filter(lambda s : exp.match(s.name), self.project.loader.symbols))
        if len(symbols) == 0:
            self.logger.critical("No symbols found matching \"", name, "\"")
            exit(-1)
        elif len(symbols) != 1:
            self.logger.critical("Multiple symbols matching\"", name, "\"found:", symbols)
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

        self.logger.debug("Located symbols:")
        self.logger.debug("  sgx_entry:              " + hex(self.sgx_entry))
        self.logger.debug("  entry:                  " + hex(self.entry))
        self.logger.debug("  image_base:             " + hex(self.image_base))
        self.logger.debug("  copy_to_userspace:      " + hex(self.copy_to_userspace))
        self.logger.debug("  copy_from_userspace:    " + hex(self.copy_from_userspace))
        self.logger.debug("  panic:                  " + hex(self.panic))
        self.logger.debug("  string_from_bytebuffer: " + hex(self.string_from_bytebuffer))
        self.logger.debug("  memcpy:                 " + hex(self.memcpy))

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

    def is_enclave_range(self, state, p, length):
        image_base = self.image_base
        enclave_size = state.memory.load(self.enclave_size, 8, disable_actions=True, inspect=False)

        if state.solver.eval(p == self.enclave_size):
            return True

        ptr = claripy.BVS("ptr", 64)

        # [p; p + length[ may be in enclave range when:
        # `ptr in [p; p + length[`
        # and `ptr in [image_base; image_base + enclave_size[`
        is_in_enclave = state.solver.satisfiable(extra_constraints=(
            p <= ptr,
            ptr < p + length,
            self.image_base <= ptr,
            ptr < (self.image_base + enclave_size),
            p + enclave_size < pow(2, 64)
            ))
        return is_in_enclave

    def is_stack_range(self, state, ptr, length):
        is_on_stack = not(state.solver.satisfiable(extra_constraints=(
            claripy.Not(
                claripy.And(
                    ptr <= self.stack_base,
                    self.stack_base - 0x1000 < ptr
                )
            ),
            )))
        return is_on_stack

    def is_gs_segment(self, state, ptr, length):
        is_on_gs = not(state.solver.satisfiable(extra_constraints=(
            state.regs.gs < pow(2, 64) - EnclaveVerification.GS_SEGMENT_SIZE,
            claripy.Not(
                claripy.And(
                    state.regs.gs <= ptr,
                    ptr < (state.regs.gs + EnclaveVerification.GS_SEGMENT_SIZE)
                )
            ),
            )))
        return is_on_gs

    def simulation_manager(self, state):
        sm = self.project.factory.simulation_manager(state)
        return sm

    def log_state(self, state):
        self.logger.debug("Regs:")
        self.logger.debug(" - %rax = " + str(state.regs.rax))
        self.logger.debug(" - %rbx = " + str(state.regs.rbx))
        self.logger.debug(" - %rcx = " + str(state.regs.rcx) + " (arg3)")
        self.logger.debug(" - %rdx = " + str(state.regs.rdx) + " (arg2)")
        self.logger.debug(" - %rsi = " + str(state.regs.rsi) + " (arg1)")
        self.logger.debug(" - %rdi = " + str(state.regs.rdi) + " (arg0)")
        self.logger.debug(" - %r8  = " + str(state.regs.r8) +  " (arg4)")
        self.logger.debug(" - %r9  = " + str(state.regs.r9) +  " (arg5)")
        self.logger.debug(" - %r10 = " + str(state.regs.r10))
        self.logger.debug(" - %r11 = " + str(state.regs.r11))
        self.logger.debug(" - %r12 = " + str(state.regs.r12))
        self.logger.debug(" - %r13 = " + str(state.regs.r13))
        self.logger.debug(" - %r14 = " + str(state.regs.r14))
        self.logger.debug(" - %r15 = " + str(state.regs.r15))
        self.logger.debug(" - %rbp = " + str(state.regs.rbp))
        self.logger.debug(" - %rsp = " + str(state.regs.rsp))
        self.logger.debug(" - %rip = " + str(state.regs.rip))
        #self.logger.debug(" - %d   = " + str(state.regs.dflag))
        #self.logger.debug(" - %e   = " + str(state.regs.eflags))
        #self.logger.debug(" - %r   = " + str(state.regs.get("rflags")))
        self.logger.debug("")

        # https://docs.angr.io/core-concepts/states#the-callstack-plugin
        self.logger.debug("Callsite (most recent last):")
        for frame in reversed(state.callstack):
            callsite = frame.call_site_addr
            function_addr = frame.func_addr
            function = self.project.loader.find_symbol(function_addr)
            if function is not None:
                function = function.name
            self.logger.debug("- " + hex(callsite) + ": call" + str(function) + "@" + hex(function_addr))
        self.logger.debug("")

        # https://docs.angr.io/core-concepts/states#the-history-plugin
        self.logger.debug("Basic block history (most recent last):")
        for address in state.history.bbl_addrs:
            symbol = self.project.loader.find_symbol(address)
            if symbol is not None:
                symbol = symbol.name
            self.logger.debug("-> " + hex(address) + "@" + str(symbol))
        self.logger.debug("")
        self.logger.debug("")

    def log_states(self, records, state_name):
        self.logger.debug("=[" + str(len(records)) + " " + state_name + " states ]=")
        for idx_state in range(0, len(records)):
            state = records[idx_state]
            self.logger.debug("[" + state_name + " state " + str (idx_state + 1) + "/" + str(len(records)) + "]")
            try:
                #self.logger.debug("Error: " + len(records[idx_state].error))
                state = records[idx_state].state
            except:
                ()
            self.log_state(state)

    def process_result(self, sm):
        ret = True

        if len(sm.found) == EnclaveVerification.MAX_STATES:
            self.logger().error("Maximum number of states reached:", EnclaveVerification.MAX_STATES)
            ret = False
        if len(sm.stashes[self.READ_VIOLATION]) != 0:
            self.logger.error("Some states reached a read violation")
            ret = False
        if len(sm.stashes[self.WRITE_VIOLATION]) != 0:
            self.logger.error("Some states reached a write violation")
            ret = False
        if len(sm.errored) != 0:
            self.logger.error("Some states reached an error")
            ret = False
        if len(sm.unconstrained) != 0:
            self.logger.error("Some states reached an unconstrained state")
            ret = False

        self.log_states(sm.stashes[self.READ_VIOLATION], "Read violation")
        self.log_states(sm.stashes[self.WRITE_VIOLATION], "Write violation")
        self.log_states(sm.found, "Found")
        self.log_states(sm.errored, "Error")
        return ret
