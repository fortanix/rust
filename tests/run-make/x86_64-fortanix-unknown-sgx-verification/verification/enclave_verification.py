# https://docs.angr.io/core-concepts/toplevel

import archinfo
import angr
import claripy
import hooker
import instructions
import logging
import re
import sys
import pyvex

from angr.calling_conventions import SimCCSystemVAMD64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

class EnclaveVerification:
    MAX_STATES = 75
    GS_SEGMENT_SIZE = 0x1000
    WRITE_VIOLATION = "WRITE_VIOLATION"
    READ_VIOLATION = "READ_VIOLATION"

    # constants values
    OFFSET_TCSLS_TOS = 0x00
    OFFSET_TCSLS_FLAGS = 0x08
    OFFSET_TCSLS_LAST_RSP = 0x10
    OFFSET_TCSLS_USER_RSP = 0X28
    OFFSET_TCSLS_USER_RETIP = 0x30
    OFFSET_TCSLS_USER_RBP = 0X38
    OFFSET_TCSLS_USER_R12 = 0x40
    OFFSET_TCSLS_USER_R13 = 0x48
    OFFSET_TCSLS_USER_R14 = 0x50
    OFFSET_TCSLS_USER_R15 = 0x58
    OFFSET_TCSLS_TCS_ADDR = 0x68

    def __init__(self, enclave_path, name):
        self.enclave = enclave_path
        self.logger = self.create_logger(name)
        self.logger.info("Load project")
        project = angr.Project(enclave_path, load_options={'auto_load_libs': False})
        #logging.getLogger('angr').setLevel('DEBUG')

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

    def find_location_aborted(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True

        # We assume the usercall function still looks like:
        #
        #   usercall:
        #      test %rcx,%rcx            /* check `abort` function argument */
        #      jnz .Lusercall_abort      /* abort is set, jump to abort code (unlikely forward conditional) */
        #      jmp .Lusercall_save_state /* non-aborting usercall */
        #   .Lusercall_abort:
        #   /* set aborted bit */
        #   movb $1,.Laborted(%rip)
        #
        # and extract the location of the .Laborted symbol
        addr = self.usercall + 7
        length = 7
        instr = self.project.loader.memory.load(addr, length)

        insn = list(md.disasm(instr, addr))[0]
        if insn.operands[0].type == X86_OP_MEM:
            base_reg = insn.operands[0].mem.base
            index = insn.operands[0].mem.index
            disp = insn.operands[0].mem.disp
            scale = insn.operands[0].mem.scale

            if insn.operands[0].mem.segment != 0:
                print("Unexpected mov instruction encoding (unrecognized segment): " + str(insn))
                exit(1)

            if insn.operands[0].mem.scale != 1:
                print("Unexpected mov instruction encoding (unexpected scale value): " + str(insn))
                exit(1)

            if insn.operands[0].mem.index != 0:
                print("Unexpected mov instruction encoding (unexpected index value): " + str(insn))
                exit(1)

            if insn.reg_name(base_reg) != "rip":
                print("Unexpected mov instruction encoding (unrecognized base reg): " + str(insn))
                exit(1)
            return disp + addr + length
        else:
            print("Unexpected mov instruction encoding")
            exit(1)

    def find_location_eexit(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True

        # We assume the usercall function still looks like:
        #
        # 0000000000019828 <sgx_entry>:
        #           19828:  65 48 89 0c 25 30 00  mov    %rcx,%gs:0x30
        #             ...
        #           19a22:  b8 04 00 00 00        mov    $0x4,%eax
        #           19a27:  0f 01 d7              enclu
        #
        # and extract the location of the .Laborted symbol
        addr = self.sgx_entry + 0x1fa
        length = 8
        instrs = self.project.loader.memory.load(addr, length)
        instrs = list(md.disasm(instrs, addr))

        # Assert we found a `mov $0x4, %eax` instruction
        mov = instrs[0]
        op0 = mov.operands[0]
        op1 = mov.operands[1]
        if mov.mnemonic != "mov":
            print("Expected mov instruction, found " + str(mov.mnemonic))
            exit(1)
        if op0.type == X86_OP_REG:
            if mov.reg_name(op0.reg) != "eax":
                print("Unexpected mov instruction (reg = " + hex(op0.reg) + ")")
                exit(1)

        if op1.type == X86_OP_IMM:
            if op1.imm != 0x4:
                print("Unexpected mov instruction (immediate = " + hex(op1.imm) + ")")
                exit(1)
        else:
            print("Unexpected mov instruction encoding")
            exit(1)

        # Assert we found an enclu instruction
        enclu = instrs[1]
        if enclu.mnemonic != "enclu":
            print("Expected enclu instruction, found " + str(enclu.mnemonic))
            exit(1)
        return enclu.address

    def find_location_call_entry(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True

        # We assume the sgx_entry function still looks like:
        #
        # 0000000000019828 <sgx_entry>:
        #    ...
        #    19980:	e8 2b 09 00 00       	callq  1a2b0 <entry>
        #    19985:	48 89 c6             	mov    %rax,%rsi
        #    ...
        #    19a1f:	0f ae e8             	lfence
        #    19a22:	b8 04 00 00 00       	mov    $0x4,%eax
        #    19a27:	0f 01 d7             	enclu
        #
        # and extract the location of the .Laborted symbol
        addr = self.sgx_entry + 0x158
        length = 5
        instrs = self.project.loader.memory.load(addr, length)
        instrs = list(md.disasm(instrs, addr))

        # Assert we found a `callq` instruction
        call = instrs[0]
        op = call.operands[0]
        if call.mnemonic != "call":
            print("Expected call instruction, found " + str(mov.mnemonic))
            exit(1)

        if op.type != X86_OP_IMM:
            print("Unexpected call instruction encoding")
            exit(1)

        return call.address

    def find_location_call_entry_ret(self):
        instr_length = 5
        return self.find_location_call_entry() + instr_length

    def enclave_entry_state(self, addr):
        arch = archinfo.arch_from_id("amd64")
        state = self.project.factory.blank_state(
                cc=SimCCSystemVAMD64(arch),
                addr=addr,
                add_options={"SYMBOLIC_WRITE_ADDRESSES", "SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"}
                )
        # Fake enclave state
        state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
        state.regs.gs = claripy.BVS("gs", 64)
        state.regs.fs = claripy.BVS("fs", 64)
        return state
        
    def call_state(self, addr, *args, **kwargs):
        arch = archinfo.arch_from_id("amd64")
        state = self.project.factory.call_state(
                addr,
                *args,
                cc=SimCCSystemVAMD64(arch),
                prototype=kwargs["prototype"],
                ret_addr=kwargs["ret_addr"],
                add_options={"SYMBOLIC_WRITE_ADDRESSES", "SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"})

        # Record locations
        self.stack_base = state.solver.eval(state.regs.rsp)

        # Fake enclave state
        state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
        state.regs.gs = claripy.BVS("gs", 64)

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

    # TODO Fix constraint: length isn't taken into account
    def is_in_region(self, state, ptr, length, region_start, region_length):
        is_in_region = not(state.solver.satisfiable(extra_constraints=(
            claripy.Not(
                claripy.And(
                    ptr <= region_start,
                    region_start - region_length < ptr
                )
            ),
            )))
        return is_in_region

    def is_on_stack(self, state, ptr, length):
        return self.is_in_region(state, ptr, length, self.stack_base, 0x1000)

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

    def read_instrs(self, state, rip):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.syntax = CS_OPT_SYNTAX_ATT
        MAXIMUM_INSTRUCTION_LENGTH = 15 # x86 instructions can't exceed 15 bytes
        max_bytes = 2 * MAXIMUM_INSTRUCTION_LENGTH

        instrs = state.memory.load(rip, max_bytes)
        instrs = state.solver.eval(instrs)
        instrs = instrs.to_bytes(max_bytes, 'big')
        instrs = list(md.disasm(instrs, 0x0))
        #print("read_instrs:")
        #for instr in instrs:
        #    print("(" + hex(instr.address) + ", " + str(instr.size) + ", " + instr.mnemonic + ", " + instr.op_str + ")")
        return instrs

    def is_aligned64(self, state, ptr):
        return not(state.solver.satisfiable(extra_constraints=(
            ptr & 0x7 != 0,
            )))

    def simulation_manager(self, state):
        sm = self.project.factory.simulation_manager(state)
        self.simulation_manager = sm
        return sm

    def run_verification(self, find, avoid, num_find=MAX_STATES):
        self.simulation_manager.explore(find=find, avoid=avoid, num_find=num_find)
        return self.process_result(self.simulation_manager, num_find)

    # Verifies whether the state reads:
    #   - enclave memory
    #   - stack space
    #   - userspace with well-aligned 8 byte granularity
    # All other read accesses pose a security threat on platforms that are vulnerable to stale data reads from xAPIC
    # (see https://github.com/rust-lang/rust/pull/100383)
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
            self.simulation_manager.stashes[EnclaveVerification.READ_VIOLATION].append(state.copy())
        
    def is_safe_userspace_write(self, state, rip):
        def is_mov_prologue(state, rip):
            def test_mov_prologue(state, rip, instrs):
                return self.read_instr(state, rip - len(instrs), len(instrs)) == instrs

            PROLOGUES = [
                instructions.MOV_DS_TO_DEREF_RAX + instructions.VERW_RAX + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_RBX + instructions.VERW_RBX + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_RCX + instructions.VERW_RCX + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_RDX + instructions.VERW_RDX + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_RSI + instructions.VERW_RSI + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_RDI + instructions.VERW_RDI + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R8  + instructions.VERW_R8  + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R9  + instructions.VERW_R9  + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R10 + instructions.VERW_R10 + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R11 + instructions.VERW_R11 + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R12 + instructions.VERW_R12 + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R13 + instructions.VERW_R13 + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R14 + instructions.VERW_R14 + instructions.LFENCE,
                instructions.MOV_DS_TO_DEREF_R15 + instructions.VERW_R15 + instructions.LFENCE]

            for prologue in PROLOGUES:
                if test_mov_prologue(state, rip, prologue):
                    return True
            return False

        if is_mov_prologue(state, rip):
            self.logger.debug("    - save move prologue: ok" )
        else:
            self.logger.debug("    - save move prologue: no" )
            return False

        instrs = self.read_instrs(state, rip)
        if instrs[1].mnemonic == "mfence" and instrs[2].mnemonic == "lfence":
            self.logger.debug("    - save move epilogue: ok" )
            return True
        else:
            self.logger.debug("    - save move epilogue: no" )
            return False

    # Verifies whether the state writes:
    #   - enclave memory
    #   - stack space
    #   - userspace with well-aligned 8 byte granularity
    #   - userspace with well-protected 1 byte granularity
    # All other write accesses pose a security threat on platforms that are vulnerable to MMIO stale data accesses
    # (see https://github.com/rust-lang/rust/pull/98126)
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
            self.logger.error("    -> Dangerous write instruction found")
            self.log_state(state)
            self.simulation_manager.stashes[EnclaveVerification.WRITE_VIOLATION].append(state.copy())

    # Verifies that the state writes:
    #   - enclave memory
    #   - stack space
    # Accesses to userspace are marked as write violations as they should be handled by specific functions
    def verify_no_userspace_writes(self, state):
        length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
        val = state.inspect.mem_write_expr
        dest = state.inspect.mem_write_address
        rip = state.solver.eval(state.regs.rip)
        self.logger.debug(hex(rip) + ": write " + str(int(length / 8)) + " bytes to " + str(dest) + "(no userspace writes)")

        if self.is_enclave_space(state, dest, length):
            self.logger.debug("    - in enclave: ok" )
            return True
        else:
            self.logger.debug("    - in enclave: no" )

        if self.is_on_stack(state, dest, length):
            self.logger.debug("    - on stack: ok" )
            return True
        else:
            self.logger.debug("    - on stack: no" )
            self.logger.debug("    -> suspicious write detected" )
            return False

    def is_above(self, state, ptr, length, region_start, region_length):
        is_above_start = not(state.solver.satisfiable(extra_constraints=(claripy.Not(region_start <= ptr),),))
        self.logger.debug("    - is above start: " + str(is_above_start))

        return is_above_start

    def is_below(self, state, ptr, length, region_start, region_length):
        is_below_end = not(state.solver.satisfiable(extra_constraints=(claripy.Not(ptr + length <= region_start + region_length),),))
        self.logger.debug("    - is below region end: " + str(is_below_end))

        return is_below_end


    def verify_write_violation(self, state, predicate):
        if not predicate(state):
            self.simulation_manager.stashes[EnclaveVerification.WRITE_VIOLATION].append(state.copy())

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
        self.logger.debug(" - %d   = " + str(state.regs.dflag))
        self.logger.debug(" - %e   = " + str(state.regs.eflags))
        self.logger.debug(" - flags= " + str(state.regs.flags))
        self.logger.debug(" - %gs  = " + str(state.regs.gs))


        if 'destination' in state.globals.keys():
            self.logger.debug("Globals:")
            self.logger.debug(" - destination = " + str(state.globals['destination']))


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
                self.logger.error("Error: ")
                self.logger.error(state.error)
                state = records[idx_state].state
            except:
                ()
            self.log_state(state)

    def process_result(self, sm, max_states):
        ret = True

        if len(sm.found) > max_states:
            self.logger.error("Maximum number of states reached:", EnclaveVerification.MAX_STATES)
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
        if len(sm.deadended) != 0:
            self.logger.error("Some states reached a deadended state")
            ret = False

        self.log_states(sm.stashes[self.READ_VIOLATION], "Read violation")
        self.log_states(sm.stashes[self.WRITE_VIOLATION], "Write violation")
        self.log_states(sm.found, "Found")
        self.log_states(sm.unconstrained, "Unconstrained")
        self.log_states(sm.errored, "Error")
        self.log_states(sm.deadended, "Deadended")
        return ret
