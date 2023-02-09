import angr
import claripy
import random
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from enclave_verification import EnclaveVerification

class TcsInit(angr.SimProcedure):
    def run(self):
        print("Simulating tcs_init function")

class VerificationEntryCode(EnclaveVerification):
    def __init__(self, enclave_path, secondary_tcs, aborted, debug, ret_usercall):
        EnclaveVerification.__init__(self, enclave_path, "VerificationEntryCode")
        self.secondary_tcs = secondary_tcs
        self.aborted = aborted
        self.debug = debug
        self.ret_usercall = ret_usercall

    def verify(self):
        def should_avoid(state):
            return False

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        # dummy values
        TOS_VALUE = random.randint(0x1000, 0x10000)
        GS_LOCATION = random.randint(0, 0x10000)
        LAST_RIP = random.randint(0x800000, 0x1000000000)

        print("Verifying with settings:")
        print(" - secondary TCS:   " + str(self.secondary_tcs))
        print(" - aborted enclave: " + str(self.aborted))
        print(" - debug:           " + str(self.debug))
        print(" - ret usercall:    " + str(self.ret_usercall))
        print(" - Top of stack:    " + hex(TOS_VALUE))
        print(" - GS segment:      " + hex(GS_LOCATION))
        print(" - last %rip:       " + hex(LAST_RIP))

        entry = self.project.loader.find_symbol("entry").rebased_addr
        tcs_init = self.project.loader.find_symbol("tcs_init").rebased_addr
        aborted = self.find_location_aborted()
        debug = self.project.loader.find_symbol("DEBUG").rebased_addr
        eexit = self.find_location_eexit()

        # Hook symbols
        self.project.hook_symbol(tcs_init, TcsInit())

        # Setting up call site
        state = self.enclave_entry_state(
                self.sgx_entry
                )

        # Setting up registers
        arg0 = state.solver.BVS("arg0", 64)
        arg1 = state.solver.BVS("arg1", 64)
        arg2 = state.solver.BVS("arg2", 64)
        arg3 = state.solver.BVS("arg3", 64)
        arg4 = state.solver.BVS("arg4", 64)
        arg5 = state.solver.BVS("arg5", 64)
        original_r12 = state.solver.BVS("r12", 64)
        original_r13 = state.solver.BVS("r12", 64)
        original_r14 = state.solver.BVS("r14", 64)
        original_r15 = state.solver.BVS("r15", 64)
        original_rbp = state.solver.BVS("rbp", 64)

        state.regs.rdi = arg0
        state.regs.rsi = arg1
        state.regs.rdx = arg2
        state.regs.rcx = arg3
        state.regs.r8 = arg4
        state.regs.r9 = arg5
        state.regs.gs = state.solver.BVV(GS_LOCATION, 64)
        state.regs.r12 = original_r12
        state.regs.r13 = original_r13
        state.regs.r14 = original_r14
        state.regs.r15 = original_r15
        state.regs.rbp = original_rbp

        # Setting up memory contents
        if self.secondary_tcs:
            tcsls_flags = 0x01
            # There's a difference in rflags based on whether we're dealing with a primary or secondary TCS
            # struct. These changes in 2 bits are harmless
            expected_rflags = 0x00
        else:
            tcsls_flags = 0x00
            expected_rflags = 0x44

        if self.aborted:
            aborted_val = 0x01
        else:
            aborted_val = 0x00

        if self.debug:
            debug_val = 0x01
        else:
            debug_val = 0x00

        if self.ret_usercall:
            last_mxcsr = state.solver.BVS("last_mxcsr", 32)
            last_cw = state.solver.BVS("last_cw", 32)
            last_rbx = state.solver.BVS("last_rbx", 64)
            last_rbp = state.solver.BVS("last_rbp", 64)
            last_r12 = state.solver.BVS("last_r12", 64)
            last_r13 = state.solver.BVS("last_r13", 64)
            last_r14 = state.solver.BVS("last_r14", 64)
            last_r15 = state.solver.BVS("last_r15", 64)
            last_rsp = state.solver.BVS("last_rsp", 64)

            # Last rsp and regs are only set during usercall when its _not_ an abort.
            if not(self.aborted):
                state.memory.store(GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_LAST_RSP, last_rsp, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 0, last_mxcsr, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 4, last_cw, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 8, last_rbx, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 16, last_rbp, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 24, last_r12, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 32, last_r13, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 40, last_r14, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 48, last_r15, endness=state.arch.memory_endness)
                state.memory.store(last_rsp + 56, state.solver.BVV(LAST_RIP, 64), endness=state.arch.memory_endness)
        else:
            last_rsp = state.solver.BVV(0x0, 64)

        # Reset gs:tcsls_last_rsp (we're only interested in normal enclave entries, not returns from usercalls)
        state.memory.store(GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_LAST_RSP, last_rsp, endness=state.arch.memory_endness)
        state.memory.store(GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_FLAGS, state.solver.BVV(tcsls_flags, 64), endness=state.arch.memory_endness)
        state.memory.store(GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_TOS, state.solver.BVV(TOS_VALUE, 64), endness=state.arch.memory_endness)
        state.memory.store(aborted, state.solver.BVV(aborted_val, 8), endness=state.arch.memory_endness)
        state.memory.store(debug, state.solver.BVV(debug_val, 8), endness=state.arch.memory_endness)

        # Running the simulation
        self.simulation_manager(state)
        if not(self.run_verification(find=lambda s : should_reach(s, entry) or should_reach(s, eexit) or should_reach(s, LAST_RIP), avoid=should_avoid)):
            return False
        else:
            for i in range(0, len(self.simulation_manager.found)):
                state = self.simulation_manager.found[i]
                if self.aborted:
                    # Aborted enclaves need to immediately exit the enclave again
                    if state.solver.satisfiable(extra_constraints=(state.regs.rip != eexit, )):
                        print("Error! Register rip has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rax != 0x4, )):
                        print("Error! Register rax has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rbx != arg3, )):
                        print("Error! Register rbx has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rcx != 0x0, )):
                        print("Error! Register rcx has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rdx != 0x0, )):
                        print("Error! Register rdx has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rsi != 0x0, )):
                        print("Error! Register rsi has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rdi != 0xa, )):
                        print("Error! Register rdi has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r8 != 0x0, )):
                        print("Error! Register r8 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r9 != 0x0, )):
                        print("Error! Register r9 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r10 != 0x0, )):
                        print("Error! Register r10 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r11 != 0x0, )):
                        print("Error! Register r11 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r12 != original_r12, )):
                        print("Error! Register r12 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r13 != original_r13, )):
                        print("Error! Register r13 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r14 != original_r14, )):
                        print("Error! Register r14 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r15 != original_r15, )):
                        print("Error! Register r15 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rbp != original_rbp, )):
                        print("Error! Register rbp has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rsp != 0x7ffffffffff0000, )):
                        print("Error! rsp set to an unexpected value (expected 0x7ffffffffff0000)")
                        return False

                elif self.ret_usercall:
                    # Enclaves that return from a usercall need to resume from the last rip again
                    if state.solver.satisfiable(extra_constraints=(state.regs.rip != LAST_RIP, )):
                        print("Error! Register rip has unexpected value (expected " + hex(LAST_RIP) + ")")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rax != arg1, )):
                        print("Error! Register rax has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rbx != last_rbx, )):
                        print("Error! Register rbx has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rcx != arg3, )):
                        print("Error! Register rcx has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rdx != arg2, )):
                        print("Error! Register rdx has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rsi != arg1, )):
                        print("Error! Register rsi has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rdi != arg0, )):
                        print("Error! Register rdi has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r8 != arg4, )):
                        print("Error! Register r8 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r9 != arg5, )):
                        print("Error! Register r9 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r10 != arg2, )):
                        print("Error! Register r10 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r11 != state.regs.rip, )):
                        print("Error! Register r11 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r12 != last_r12, )):
                        print("Error! Register r12 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r13 != last_r13, )):
                        print("Error! Register r13 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r14 != last_r14, )):
                        print("Error! Register r14 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r15 != last_r15, )):
                        print("Error! Register r15 has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rbp != last_rbp, )):
                        print("Error! Register rbp has unexpected value")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rsp != last_rsp + 0x40, )):
                        print("Error! rsp set to an unexpected value (expected last_rsp + 0x40)")
                        return False

                    mem_last_rsp = state.memory.load(GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_LAST_RSP, 8, disable_actions=True, inspect=False)
                    if state.solver.satisfiable(extra_constraints=(mem_last_rsp != 0x0, )):
                        print("gs:tcsls_last_rsp is not reset")
                        exit(1)
                else:
                    # Initial enclave calls need to call `entry()`
                    if state.solver.satisfiable(extra_constraints=(state.regs.rip != entry, )):
                        print("Error! Register rip has unexpected value (expected " + hex(LAST_RIP) + ")")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rdi != arg0, )):
                        print("Error! Argument 0 not passed unchanged to Rust code")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rsi != arg1, )):
                        print("Error! Argument 1 not passed unchanged to Rust code")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rdx != arg2, )):
                        print("Error! Argument 2 not passed unchanged to Rust code")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rcx != tcsls_flags, )):
                        print("Error! Argument 3 does not express whether we're on a secondary TCS to Rust code")
                        return False

                    # User input arg3 is missing! It doesn't cause problems, but is unexpected given the parameter naming in the entry function
                    # see: library/std/src/sys/sgx/abi/mod.rs

                    if state.solver.satisfiable(extra_constraints=(state.regs.r8 != arg4, )):
                        print("Error! Argument 4 does not express whether we're on a secondary TCS to Rust code")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.r9 != arg5, )):
                        print("Error! Argument 5 does not express whether we're on a secondary TCS to Rust code")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.rsp != TOS_VALUE + self.image_base - 8, )):
                        print("Error! rsp set to an unexpected value (expected " + hex(self.image_base + TOS_VALUE - 8) + ")")
                        return False

                    if state.solver.satisfiable(extra_constraints=(state.regs.flags != expected_rflags, )):
                        print("Error! rflags have an unexpected value (expected " + hex(expected_rflags) + ")")
                        return False

                # Verify common state
                if not(state.globals["xsave_initialization"]):
                    print("Processor state not initialized through xrstor!")
                    return False

            print("Verified successfully!!!")
            return True

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        print("Verifying entry code implementation...................", end="")
        for ret_usercall in [True, False]:
            for debug in [True, False]:
                for aborted in [True, False]:
                    for secondary_tcs in [True, False]:
                        if not(VerificationEntryCode(enclave_path, secondary_tcs=secondary_tcs, aborted=aborted, debug=debug, ret_usercall=ret_usercall).verify()):
                            print("Failed")
                            exit(-1)
        print("Succeeded")
