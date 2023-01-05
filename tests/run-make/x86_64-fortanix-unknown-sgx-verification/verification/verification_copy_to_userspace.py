import angr
import claripy
import sys
from enclave_verification import EnclaveVerification

INSTR_LFENCE = b'\x0f\xae\xe8'
INSTR_MFENCE = b'\x0f\xae\xf0'

class VerificationCopyToUserspace(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path, "VerificationCopyToUserspace")

    def verify(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic) or state.solver.eval(state.regs.rip == self.panic_with_hook)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        # Setting up call site
        end = 0x0
        state = self.call_state(
                self.copy_to_userspace,
                ret_addr=end,
                prototype="void copy_to_userspace(uint8_t const *src, uint8_t *dst, size_t len)")

        # Setting up break points
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s : self.verify_safe_userspace_writes(s))

        # Running the simulation
        self.simulation_manager(state)
        return self.run_verification(find=lambda s : should_reach(s, end), avoid=should_avoid)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        print("Verifying copy_to_userspace implementation............", end="")
        if not(VerificationCopyToUserspace(enclave_path).verify()):
            print("Failed")
            exit(-1)
        else:
            print("Succeeded")
