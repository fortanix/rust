import logging
import sys
from enclave_verification import EnclaveVerification

# Verifies the functional correctness of the `get_image_base` functiont: The value returned by `get_image_base` must be equal to the location of the `image_base` symbol
class VerificationImageBase(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path, "VerificationImageBase")
        self.logger.info('Initialized')

    def verify(self):
         def should_avoid(state):
             return state.solver.eval(state.regs.rip == self.panic)
 
         def should_reach(state, end):
             return state.solver.eval(state.regs.rip == end)
 
         end = 0x0
         state = self.call_state(
                 self.project.loader.find_symbol("get_image_base").rebased_addr,
                 ret_addr=end,
                 prototype="uint64_t get_image_base(void)")
         self.simulation_manager(state)
 
         if self.run_verification(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=1):
             assert(self.simulation_manager.found[0].solver.eval(self.simulation_manager.found[0].regs.rax == self.image_base))
             return True
         else:
            return False

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        print("Verifying image_base implementation...................", end="")
        if not(VerificationImageBase(enclave_path).verify()):
            print("Failed")
            exit(-1)
        else:
            print("Succeeded")
