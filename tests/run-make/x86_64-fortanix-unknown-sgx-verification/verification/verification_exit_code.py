import angr
import claripy
import random
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from enclave_verification import EnclaveVerification

class VerificationExitCode(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path, "VerificationExitCode")

    def verify(self):
        def should_avoid(state):
            return False

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        call_entry_ret = self.find_location_call_entry_ret()
        eexit = self.find_location_eexit()

        # dummy values
        EnclaveVerification.GS_LOCATION = random.randint(0, 0x10000)

        print("Verifying with settings:")
        print(" - GS segment:      " + hex(EnclaveVerification.GS_LOCATION))

        # Setting up call site
        state = self.enclave_entry_state(
                call_entry_ret
                )

        # Setting up registers
        ret_val0 = state.solver.BVS("ret_val0", 64)
        ret_val1 = state.solver.BVS("ret_val1", 64)

        state.regs.rax = ret_val0
        state.regs.rdx = ret_val1
        state.regs.gs = state.solver.BVV(EnclaveVerification.GS_LOCATION, 64)

        # Setting up memory contents
        user_retip = state.solver.BVS("user_retip", 64)
        user_r12 = state.solver.BVS("user_r12", 64)
        user_r13 = state.solver.BVS("user_r13", 64)
        user_r14 = state.solver.BVS("user_r14", 64)
        user_r15 = state.solver.BVS("user_r15", 64)
        user_rbp = state.solver.BVS("user_rbp", 64)
        user_rsp = state.solver.BVS("user_rsp", 64)

        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R12, user_r12, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R13, user_r13, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R14, user_r14, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R15, user_r15, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_RBP, user_rbp, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_RSP, user_rsp, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_RETIP, user_retip, endness=state.arch.memory_endness)

        # Running the simulation
        self.simulation_manager(state)
        if not(self.run_verification(find=lambda s : should_reach(s, eexit), avoid=should_avoid)):
            return False
        else:
            for i in range(0, len(self.simulation_manager.found)):
                state = self.simulation_manager.found[i]
                if state.solver.satisfiable(extra_constraints=(state.regs.rip != eexit, )):
                    print("Error! Register rip has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rax != 0x4, )):
                    print("Error! Register rax has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rbx != user_retip, )):
                    print("Error! Register rbx has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rcx != ret_val1, )):
                    print("Error! Register rcx has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rdx != ret_val1, )):
                    print("Error! Register rdx has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rsi != ret_val0, )):
                    print("Error! Register rsi has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rdi != 0x0, )):
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

                if state.solver.satisfiable(extra_constraints=(state.regs.r12 != user_r12, )):
                    print("Error! Register r12 has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r13 != user_r13, )):
                    print("Error! Register r13 has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r14 != user_r14, )):
                    print("Error! Register r14 has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r15 != user_r15, )):
                    print("Error! Register r15 has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rbp != user_rbp, )):
                    print("Error! Register rbp has unexpected value")
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rsp != user_rsp, )):
                    print("Error! Register rsp has unexpected value")
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

        print("Verifying exit code implementation....................", end="")
        if not(VerificationExitCode(enclave_path).verify()):
            print("Failed")
            exit(-1)
        print("Succeeded")
