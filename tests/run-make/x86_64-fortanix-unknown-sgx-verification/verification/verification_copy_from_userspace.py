import angr
import claripy
import sys
from enclave_verification import EnclaveVerification

class VerificationCopyFromUserspace(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path, "VerificationCopyFromUserspace")

    def destination_area(self, state):
        length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
        val = state.inspect.mem_write_expr
        dest = state.inspect.mem_write_address
        rip = state.solver.eval(state.regs.rip)
        self.logger.debug(hex(rip) + ": write " + str(int(length / 8)) + " bytes to " + str(dest) + "(exception)")
        dest_base = state.globals['destination_ptr']
        self.logger.debug("destination_ptr = " + str(dest_base))
        dest_length = state.globals['destination_length']
        self.logger.debug("destination_length = " + str(dest_length))

        # WARNING Verifying if ptr in destination area fails verification as we fail to keep track
        # of information build up by the application. We already verified that:
        #  - is_enclave_range(dst, len)
        #  - len < 8, or len % 8 == 0 && src as usize % 8 == 0, or we split the region to fit
        #    any of these constraints
        if self.is_above(state, dest, length, dest_base, dest_length):
            self.logger.debug("    in destination area: ok")
            return True
        else:
            self.logger.debug("    in destination area: no")
            return False

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

        destination = state.solver.BVS("arg1_dst", 64)
        length = state.solver.BVS("arg2_len", 64)

        state.regs.rdi = state.solver.BVS("arg0_src", 64)
        state.regs.rsi = destination
        state.regs.rdx = length
        state.regs.gs  = state.solver.BVS("gs", 64)
        state.globals['destination_ptr'] = destination
        state.globals['destination_length'] = length

        # Setting up break points
        # See https://docs.angr.io/core-concepts/simulation#caution-about-mem_read-breakpoint
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=lambda s : self.verify_safe_userspace_reads(s))
        # WARNING: writes to exception region is ok as long as the source is from within the enclave!
        state.inspect.b('mem_write',
                when=angr.BP_BEFORE,
                action=lambda s : self.verify_write_violation(s, (lambda state : (self.verify_no_userspace_writes(state) or self.destination_area(state))))
                )

        # Running the simulation
        self.simulation_manager(state)
        return self.run_verification(find=lambda s : should_reach(s, end), avoid=should_avoid)

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
