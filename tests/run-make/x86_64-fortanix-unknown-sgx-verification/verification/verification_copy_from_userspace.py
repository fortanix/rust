import angr
import claripy
import sys
from enclave_verification import EnclaveVerification

class VerificationCopyFromUserspace(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path, "VerificationCopyFromUserspace")

    def verify(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic) or state.solver.eval(state.regs.rip == self.panic_with_hook)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        # Setting up call site
        end = 0x0
        state = self.call_state(
                self.copy_from_userspace,
                ret_addr=end,
                prototype="void copy_from_userspace(uint8_t const *src, uint8_t *dst, size_t len)")
        state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))

        image_base = self.image_base
        enclave_size = state.memory.load(self.enclave_size, 8)
        self.stack_base = state.solver.eval(state.regs.rsp)

        # Setting up break points
        # See https://docs.angr.io/core-concepts/simulation#caution-about-mem_read-breakpoint
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=lambda s : self.verify_safe_userspace_reads(s))

        # Running the simulation
        sm = self.simulation_manager(state)
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=EnclaveVerification.MAX_STATES)

        # Print results
        return self.process_result(sm)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        print("Verifying copy_from_userspace implementation..........", end="")
        if not(VerificationCopyFromUserspace(enclave_path).verify()):
            print("Failed")
            exit(-1)
        else:
            print("Succeeded")
