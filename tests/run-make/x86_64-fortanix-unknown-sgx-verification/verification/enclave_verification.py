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

    def is_enclave_space(self, state, p, length):
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

    def is_on_stack(self, state, ptr, length):
        is_on_stack = not(state.solver.satisfiable(extra_constraints=(
            claripy.Not(
                claripy.And(
                    ptr <= self.stack_base,
                    self.stack_base - 0x1000 < ptr
                )
            ),
            )))
        return is_on_stack

    def is_on_gs_segment(self, state, ptr, length):
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

    def read_instr(self, state, rip, length):
        instr = state.memory.load(rip, length)
        instr = state.solver.eval(instr)
        instr = instr.to_bytes(length, 'big')
        #self.logger.debug("instr =" + instr + "(type =" + type(instr) + ")")
        return instr

    def is_aligned64(self, state, ptr):
        return not(state.solver.satisfiable(extra_constraints=(
            ptr & 0x7 != 0,
            )))

    def simulation_manager(self, state):
        sm = self.project.factory.simulation_manager(state)
        return sm

    def verify_safe_userspace_reads(self, state):
        length = state.solver.eval(state.inspect.mem_read_length) if state.inspect.mem_read_length is not None else len(state.inspect.mem_read_expr)
        val = state.inspect.mem_read_expr
        dest = state.inspect.mem_read_address
        rip = state.solver.eval(state.regs.rip)
        self.logger.debug(hex(rip) + ": read " + str(int(length / 8)) + " bytes from " + str(dest))

        # We're not enforcing that the stack is part of the enclave for now. We just assume it's relative to the rsp
        if self.is_enclave_space(state, dest, length):
            self.logger.debug("    - in enclave: ok" )
        elif self.is_on_stack(state, dest, length):
            self.logger.debug("    - on stack: ok" )
        elif length == 64 and self.is_aligned64(state, dest):
            self.logger.debug("    - length: 8 bytes" )
            self.logger.debug("    - well aligned: ok")
        else:
            self.logger.error(hex(rip) + ": read " + str(int(length / 8)) + "bytes from" + hex(dest))
            self.logger.error("    - in enclave: no" )
            self.logger.error("    - on stack: no" )
            self.logger.error("    - well aligned: no")
            self.logger.error("    -> Dangerous read instruction found")
            self.log_state(state)
            sm.stashes[EnclaveVerification.READ_VIOLATION].append(state.copy())
        
    def is_safe_userspace_write(self, state, rip):
        def is_mov_prologue(state, rip):
            def test_mov_prologue(state, rip, instrs):
                return self.read_instr(state, rip - len(instrs), len(instrs)) == instrs

            # mov    %ds,(%rax)
            MOV_DS_TO_PTR_RAX = b'\x8c\x18'

            # mov    %ds,(%rbx)
            MOV_DS_TO_PTR_RBX = b'\x8c\x1b'

            # mov    %ds,(%rcx)
            MOV_DS_TO_PTR_RCX = b'\x8c\x19'

            # mov    %ds,(%rdx)
            MOV_DS_TO_PTR_RDX = b'\x8c\x1a'

            # mov    %ds,(%rsi)
            MOV_DS_TO_PTR_RSI = b'\x8c\x1e'

            # mov    %ds,(%rdi)
            MOV_DS_TO_PTR_RDI = b'\x8c\x1f'

            # mov    %ds,(%r8)
            MOV_DS_TO_PTR_R8 = b'\x41\x8c\x18'

            # mov    %ds,(%r9)
            MOV_DS_TO_PTR_R9 = b'\x41\x8c\x19'

            # mov    %ds,(%r10)
            MOV_DS_TO_PTR_R10 = b'\x41\x8c\x1a'

            # mov    %ds,(%r11)
            MOV_DS_TO_PTR_R11 = b'\x41\x8c\x1b'

            # mov    %ds,(%r12)
            MOV_DS_TO_PTR_R12 = b'\x41\x8c\x1c\x24'

            # mov    %ds,(%r13)
            MOV_DS_TO_PTR_R13 = b'\x41\x8c\x5d\x00'

            # mov    %ds,(%r14)
            MOV_DS_TO_PTR_R14 = b'\x41\x8c\x1e'

            # mov    %ds,(%r15)
            MOV_DS_TO_PTR_R15 = b'\x41\x8c\x1f'

            # 0f 00 28             	verw   (%rax)
            VERW_RAX = b'\x0f\x00\x28'

            # 0f 00 2b             	verw   (%rbx)
            VERW_RBX = b'\x0f\x00\x2b'

            # 0f 00 29             	verw   (%rcx)
            VERW_RCX = b'\x0f\x00\x29'

            # 0f 00 2a             	verw   (%rdx)
            VERW_RDX = b'\x0f\x00\x2a'

            # 0f 00 2e             	verw   (%rsi)
            VERW_RSI = b'\x0f\x00\x2e'

            # 0f 00 2f             	verw   (%rdi)
            VERW_RDI = b'\x0f\x00\x2f'

            # 41 0f 00 28          	verw   (%r8)
            VERW_R8 = b'\x41\x0f\x00\x28'

            # 41 0f 00 29          	verw   (%r9)
            VERW_R9 = b'\x41\x0f\x00\x29'

            # 41 0f 00 2a          	verw   (%r10)
            VERW_R10 = b'\x41\x0f\x00\x2a'

            # 41 0f 00 2b          	verw   (%r11)
            VERW_R11 = b'\x41\x0f\x00\x2b'

            # 41 0f 00 2c 24       	verw   (%r12)
            VERW_R12 = b'\x41\x0f\x00\x2c'

            # 41 0f 00 6d 00       	verw   0x0(%r13)
            VERW_R13 = b'\x41\x0f\x00\x6d\x00'

            # 41 0f 00 2e          	verw   (%r14)
            VERW_R14 = b'\x41\x0f\x00\x2e'

            # 41 0f 00 2f          	verw   (%r15)
            VERW_R15 = b'\x41\x0f\x00\x2f'

            PROLOGUES = [
                MOV_DS_TO_PTR_RAX + VERW_RAX + INSTR_LFENCE,
                MOV_DS_TO_PTR_RBX + VERW_RBX + INSTR_LFENCE,
                MOV_DS_TO_PTR_RCX + VERW_RCX + INSTR_LFENCE,
                MOV_DS_TO_PTR_RDX + VERW_RDX + INSTR_LFENCE,
                MOV_DS_TO_PTR_RSI + VERW_RSI + INSTR_LFENCE,
                MOV_DS_TO_PTR_RDI + VERW_RDI + INSTR_LFENCE,
                MOV_DS_TO_PTR_R8  + VERW_R8  + INSTR_LFENCE,
                MOV_DS_TO_PTR_R9  + VERW_R9  + INSTR_LFENCE,
                MOV_DS_TO_PTR_R10 + VERW_R10 + INSTR_LFENCE,
                MOV_DS_TO_PTR_R11 + VERW_R11 + INSTR_LFENCE,
                MOV_DS_TO_PTR_R12 + VERW_R12 + INSTR_LFENCE,
                MOV_DS_TO_PTR_R13 + VERW_R13 + INSTR_LFENCE,
                MOV_DS_TO_PTR_R14 + VERW_R14 + INSTR_LFENCE,
                MOV_DS_TO_PTR_R15 + VERW_R15 + INSTR_LFENCE]

            for prologue in PROLOGUES:
                if test_mov_prologue(state, rip, prologue):
                    return True
            return False

        def is_mov_epilogue(state, rip):
            def test_mov_epilogue(state, rip, instrs):
                return self.read_instr(state, rip, len(instrs)) == instrs
            return test_mov_epilogue(state, rip, INSTR_MFENCE + INSTR_LFENCE)

        if is_mov_prologue(state, rip):
            self.logger.debug("    - save move prologue: ok" )
        else:
            self.logger.debug("    - save move prologue: no" )

        if is_mov_epilogue(state, rip + 2):
            self.logger.debug("    - save move epilogue: ok" )
        else:
            self.logger.debug("    - save move epilogue: no" )

        return is_mov_prologue(state, rip) and is_mov_epilogue(state, rip + 2)

    def verify_safe_userspace_writes(self, state):
        length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
        val = state.inspect.mem_write_expr
        dest = state.inspect.mem_write_address
        rip = state.solver.eval(state.regs.rip)
        self.logger.debug(hex(rip) + ": write " + str(int(length / 8)) + " bytes to " + str(dest))

        # We're not enforcing that the stack is part of the enclave for now. We just assume it's relative to the rsp
        if self.is_enclave_space(state, dest, length):
            self.logger.debug("    - in enclave: ok" )
        elif self.is_on_stack(state, dest, length):
            self.logger.debug("    - on stack: ok" )
        elif length == 8 and self.is_safe_userspace_write(state, rip):
            self.logger.debug("    - safe userspace write: ok" )
        elif length == 64 and self.is_aligned64(state, dest):
            self.logger.debug("    - well-aligned aligned 8-byte write: ok" )
        else:
            self.logger.error(hex(rip) + ": write " + str(int(length / 8)) + " bytes to " + str(dest))
            self.logger.error("    - in enclave: no" )
            self.logger.error("    - on stack: no" )
            self.log_state(state)
            sm.stashes[EnclaveVerification.WRITE_VIOLATION].append(state.copy())

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
