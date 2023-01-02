import claripy
import sys
from enclave_verification import EnclaveVerification

class VerificationIsEnclaveRange(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path)

    def verify(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        print("Verifying is_enclave_range implementation...")
        end = 0x0
        p = claripy.BVS("p", 64)
        len_ = claripy.BVS("len", 64)

        state = self.call_state(
                self.project.loader.find_symbol("verify_is_enclave_range").rebased_addr,
                p,
                len_,
                ret_addr=end,
                prototype="int is_enclave_range(uint8_t const *p, size_t length)") 

        # Fake enclave state
        enclave_size = state.solver.BVS("enlave_size", 64);
        state.memory.store(self.enclave_size, enclave_size)

        # Simulate function call
        sm = self.simulation_manager(state)
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=EnclaveVerification.MAX_STATES)

        if not(self.process_result(sm)):
            return False
        else:
            for i in range(0, len(sm.found)):
                print("state: ", i)
                state = sm.found[i]
                # Make a symbolic variable for the result
                result = claripy.BVS("result", 64)
                state.solver.add(result == state.regs.rax)

                # If `p in [image_base; image_base + enclave_size[`
                # and `p + len_ in [image_base; image_base + enclave_size[`
                # the result must be true
                if state.solver.satisfiable(extra_constraints=(
                    self.image_base <= p,
                    p < (self.image_base + enclave_size),
                    self.image_base <= (p + len_),
                    (p + len_) <= (self.image_base + enclave_size),
                    result == 0,

                    # Warning: this additional constraint is required because Angr doesn't properly handle
                    #   the `(p as usize).checked_add(len - 1)` call
                    p + enclave_size < pow(2, 64)
                    )):

                    print("Counter examples found:")
                    result = state.solver._solver.batch_eval([result, p, len_, self.image_base, enclave_size], 3)
                    for (result, p, len_, base, size) in result:
                        print("result = ", result)
                        print("p =", hex(p))
                        print("len_ =", hex(len_))
                        print("area range = [", hex(p), ",", hex(p + len_), "[")
                        print("enclave size =", hex(size))
                        print("enclave base =", hex(base))
                        print("enclave range = [", hex(base), ",", hex(base + size), "[")
                        print("const 0: ", base <= p)
                        print("const 1: ", p < (base + size))
                        print("const 2: ", base <= (p + len_))
                        print("const 3: ", (p + len_) <= (base + size))
                        print("const 4: ", result == 0)
                        print("constraints:", state.solver._solver.constraints)
                        print("")

                    print("Verification failed")
                    return False

                # If there exists a `ptr` such that `ptr not in [image_base; image_base + enclave_size[`
                # and `ptr in [p; p + len_[`
                # the result must be false
                ptr = claripy.BVS("ptr", 64)
                if state.solver.satisfiable(extra_constraints=(
                    claripy.Not(
                        claripy.And(
                            self.image_base <= ptr,
                            ptr < (self.image_base + enclave_size)
                        )),
                    p <= ptr,
                    ptr < (self.image_base + enclave_size),
                    result != 0,

                    # Warning: this additional constraint is required because Angr doesn't properly handle
                    #   the `(p as usize).checked_add(len - 1)` call
                    p + enclave_size < pow(2, 64)
                    )):

                    print("Counter examples found:")
                    result = state.solver._solver.batch_eval([result, p, len_, self.image_base, enclave_size], 3)
                    for (result, p, len_, base, size) in result:
                        print("result = ", result)
                        print("p =", hex(p))
                        print("len_ =", hex(len_))
                        print("area range = [", hex(p), ",", hex(p + len_), "[")
                        print("enclave size =", hex(size))
                        print("enclave base =", hex(base))
                        print("enclave range = [", hex(base), ",", hex(base + size), "[")
                        print("const 0: ", base <= p)
                        print("const 1: ", p < (base + size))
                        print("const 2: ", base <= (p + len_))
                        print("const 3: ", (p + len_) <= (base + size))
                        print("const 4: ", result == 0)
                        print("constraints:", state.solver._solver.constraints)
                        print("")

                    print("Verification failed")
                    return False
            return True

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        enclave = VerificationIsEnclaveRange(enclave_path)
        if not(enclave.verify()):
            exit(-1)
        else:
            print("SUCCESS")
