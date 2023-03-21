import angr
import claripy
import random
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from enclave_verification import EnclaveVerification

class VerificationUsercallAsm(EnclaveVerification):
    def __init__(self, enclave_path, aborted):
        EnclaveVerification.__init__(self, enclave_path, "VerificationUsercallAsm")
        self.aborted = aborted

    def verify(self):
        def should_avoid(state):
            return False

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        # dummy values
        EnclaveVerification.GS_LOCATION = random.randint(0, 0x10000)
        EnclaveVerification.LAST_RIP = random.randint(0x800000, 0x1000000000)
        if self.aborted:
            aborted_val = random.randint(1, 0x1000000000)
        else:
            aborted_val = 0x0

        self.logger.debug("Verifying with settings:")
        self.logger.debug(" - Aborted:         " + str(self.aborted))
        self.logger.debug(" - GS segment:      " + hex(EnclaveVerification.GS_LOCATION))
        self.logger.debug(" - Last rip:        " + hex(EnclaveVerification.LAST_RIP))

        # Find symbols
        eexit = self.find_location_eexit()
        aborted = self.find_location_aborted()

        # Setting up call site
        state = self.enclave_entry_state(
                self.usercall
                )

        # Setting up registers
        arg_nr = state.solver.BVS("arg_nr", 64)
        arg_p1 = state.solver.BVS("arg_p1", 64)
        arg_p2 = state.solver.BVS("arg_p2", 64)
        arg_abort = state.solver.BVV(aborted_val, 64)
        arg_p3 = state.solver.BVS("arg_p3", 64)
        arg_p4 = state.solver.BVS("arg_p4", 64)
        enclave_rbx = state.solver.BVS("enclave_rbx", 64)
        enclave_r12 = state.solver.BVS("enclave_r12", 64)
        enclave_r13 = state.solver.BVS("enclave_r13", 64)
        enclave_r14 = state.solver.BVS("enclave_r14", 64)
        enclave_r15 = state.solver.BVS("enclave_r15", 64)
        enclave_rbp = state.solver.BVS("enclave_rbp", 64)
        enclave_rsp = state.solver.BVS("enclave_rsp", 64)

        state.regs.rdi = arg_nr
        state.regs.rsi = arg_p1
        state.regs.rdx = arg_p2
        state.regs.rbx = enclave_rbx
        state.regs.rcx = arg_abort
        state.regs.r8 = arg_p3
        state.regs.r9 = arg_p4
        state.regs.gs = state.solver.BVV(EnclaveVerification.GS_LOCATION, 64)
        state.regs.r12 = enclave_r12
        state.regs.r13 = enclave_r13
        state.regs.r14 = enclave_r14
        state.regs.r15 = enclave_r15
        state.regs.rbp = enclave_rbp
        state.regs.rsp = enclave_rsp

        # Setting up memory contents
        user_mxcsr = state.solver.BVS("user_mxcsr", 32)
        user_cw = state.solver.BVS("user_cw", 32)
        tcs_addr = state.solver.BVS("tcs_addr", 64)
        user_retip = state.solver.BVS("user_retip", 64)
        user_r12 = state.solver.BVS("user_r12", 64)
        user_r13 = state.solver.BVS("user_r13", 64)
        user_r14 = state.solver.BVS("user_r14", 64)
        user_r15 = state.solver.BVS("user_r15", 64)
        user_rbp = state.solver.BVS("user_rbp", 64)
        user_rsp = state.solver.BVS("user_rsp", 64)
        last_rsp = state.solver.BVV(0x0, 64)

        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_LAST_RSP, last_rsp, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R12, user_r12, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R13, user_r13, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R14, user_r14, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_R15, user_r15, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_RBP, user_rbp, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_RSP, user_rsp, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_USER_RETIP, user_retip, endness=state.arch.memory_endness)
        state.memory.store(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_TCS_ADDR, tcs_addr, endness=state.arch.memory_endness)
        state.memory.store(user_rsp + 56, state.solver.BVV(EnclaveVerification.LAST_RIP, 64), endness=state.arch.memory_endness)

        # Running the simulation
        self.simulation_manager(state)
        if not(self.run_verification(find=lambda s : should_reach(s, eexit), avoid=should_avoid)):
            return False
        else:
            for i in range(0, len(self.simulation_manager.found)):
                state = self.simulation_manager.found[i]

                # Verify registers
                if state.solver.satisfiable(extra_constraints=(state.regs.rax != 0x4, )):
                    self.logger.error("Error! Register rax has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rbx != user_retip, )):
                    self.logger.error("Error! Register rbx has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rcx != arg_p2, )):
                    self.logger.error("Error! Register rcx has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rdx != arg_p2, )):
                    self.logger.error("Error! Register rdx has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rsi != arg_p1, )):
                    self.logger.error("Error! Register rsi has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rdi != arg_nr, )):
                    self.logger.error("Error! Register rdi has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r8 != arg_p3, )):
                    self.logger.error("Error! Register r8 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r9 != arg_p4, )):
                    self.logger.error("Error! Register r9 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r10 != 0x0, )):
                    self.logger.error("Error! Register r10 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r11 != 0x0, )):
                    self.logger.error("Error! Register r11 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r12 != user_r12, )):
                    self.logger.error("Error! Register r12 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r13 != user_r13, )):
                    self.logger.error("Error! Register r13 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r14 != user_r14, )):
                    self.logger.error("Error! Register r14 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.r15 != user_r15, )):
                    self.logger.error("Error! Register r15 has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rbp != user_rbp, )):
                    self.logger.error("Error! Register rbp has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rsp != user_rsp, )):
                    self.logger.error("Error! Register rsp has unexpected value")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if state.solver.satisfiable(extra_constraints=(state.regs.rflags != 0x0, )):
                    self.logger.error("Error! Register rflags has unexpected value (rflags = " + str(state.solver.eval(state.regs.rflags)) + ")")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                if not(state.globals["xsave_initialization"]):
                    self.logger.error("Processor state not initialized through xrstor!")
                    self.logger.error("State:")
                    self.log_state(state)
                    return False

                mem_last_rsp = state.memory.load(EnclaveVerification.GS_LOCATION + EnclaveVerification.OFFSET_TCSLS_LAST_RSP, 8, disable_actions=True, inspect=False)
                mem_aborted = state.memory.load(aborted, 1, endness=state.arch.memory_endness)
                if self.aborted:
                    if state.solver.satisfiable(extra_constraints=(mem_last_rsp != 0x0, )):
                        self.logger.error("gs:tcsls_last_rsp not set correctly")
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    if state.solver.satisfiable(extra_constraints=(mem_aborted == 0x0, )):
                        self.logger.error("aborted value not set correctly")
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)
                else:
                    if state.solver.satisfiable(extra_constraints=(mem_last_rsp != claripy.Reverse(0xffffffffffffffc8 + enclave_rsp), )):
                        self.logger.error("gs:tcsls_last_rsp not set correctly")
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    if state.solver.satisfiable(extra_constraints=(mem_aborted != 0x0, )):
                        self.logger.error("aborted value not set correctly")
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    mem_r15 = state.memory.load(enclave_rsp - 1 * 8, 8, endness=state.arch.memory_endness)
                    if state.solver.satisfiable(extra_constraints=(mem_r15 != enclave_r15, )):
                        self.logger.error("enclave r15 value not stored correctly")
                        self.logger.error(mem_r15)
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    mem_r14 = state.memory.load(enclave_rsp - 2 * 8, 8, endness=state.arch.memory_endness)
                    if state.solver.satisfiable(extra_constraints=(mem_r14 != enclave_r14, )):
                        self.logger.error("enclave r14 value not stored correctly")
                        self.logger.error(mem_r14)
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    mem_r13 = state.memory.load(enclave_rsp - 3 * 8, 8, endness=state.arch.memory_endness)
                    if state.solver.satisfiable(extra_constraints=(mem_r13 != enclave_r13, )):
                        self.logger.error("enclave r13 value not stored correctly")
                        self.logger.error(mem_r13)
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    mem_r12 = state.memory.load(enclave_rsp - 4 * 8, 8, endness=state.arch.memory_endness)
                    if state.solver.satisfiable(extra_constraints=(mem_r12 != enclave_r12, )):
                        self.logger.error("enclave r12 value not stored correctly")
                        self.logger.error(mem_r12)
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    mem_rbp = state.memory.load(enclave_rsp - 5 * 8, 8, endness=state.arch.memory_endness)
                    if state.solver.satisfiable(extra_constraints=(mem_rbp != enclave_rbp, )):
                        self.logger.error("enclave rbp value not stored correctly")
                        self.logger.error(mem_rbp)
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    mem_rbx = state.memory.load(enclave_rsp - 6 * 8, 8, endness=state.arch.memory_endness)
                    if state.solver.satisfiable(extra_constraints=(mem_rbx != enclave_rbx, )):
                        self.logger.error("enclave rbx value not stored correctly")
                        self.logger.error(mem_rbx)
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

                    if state.solver.satisfiable(extra_constraints=(mem_aborted != 0x0, )):
                        self.logger.error("aborted value not set correctly")
                        self.logger.error("State:")
                        self.log_state(state)
                        exit(1)

            self.logger.debug("Verified successfully!!!")
            return True

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        print("Verifying usercall code implementation...................", end="")
        for aborted in [False, True]:
            if not(VerificationUsercallAsm(enclave_path, aborted=aborted).verify()):
                print("Failed")
                exit(-1)
        print("Succeeded")
