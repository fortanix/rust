import angr
import claripy
import sys
from enclave_verification import EnclaveVerification

class VerificationCopyFromUserspace(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path)

    def verify(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic) or state.solver.eval(state.regs.rip == self.panic_with_hook)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        def is_enclave_range(state, p, length):
            image_base = self.image_base
            enclave_size = state.memory.load(self.enclave_size, 8, disable_actions=True, inspect=False)
            #print("enclave_size =", enclave_size)
            #print("image_size =", hex(image_base))

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
            print("is in enclave range: ", is_in_enclave)
            return is_in_enclave

        def is_stack_range(state, dest, length):
            print("is_stack_range: dest:", dest, "len:", length)
            print("is_stack_range: stack base:", hex(self.stack_base))
            is_on_stack = not(state.solver.satisfiable(extra_constraints=(
                claripy.Not(
                    claripy.And(
                        dest <= self.stack_base,
                        self.stack_base - 0x1000 < dest
                    )
                ),
                )))
            print("is on stack:", is_on_stack)
            return is_on_stack

        def is_aligned64(state, dest):
            return not(state.solver.satisfiable(extra_constraints=(
                dest & 0x7 != 0,
                )))

        def read_instr(state, rip, length):
            instr = state.memory.load(rip, length)
            instr = state.solver.eval(instr)
            instr = instr.to_bytes(length, 'big')
            #print("instr =", instr, "(type =", type(instr), ")")
            return instr

        def track_read(state, p):
            length = state.solver.eval(state.inspect.mem_read_length) if state.inspect.mem_read_length is not None else len(state.inspect.mem_read_expr)
            val = state.inspect.mem_read_expr
            dest = state.inspect.mem_read_address
            rip = state.solver.eval(state.regs.rip)

            # We're not enforcing that the stack is part of the enclave for now. We just assume it's relative to the rsp
            if not(is_enclave_range(state, dest, length)) and not(is_stack_range(state, dest, length)):
                print("Reading outside of enclave at", hex(rip), "(dest =", dest, ", len =", int(length / 8), "bytes)")
                if length == 64:
                    if is_aligned64(state, dest):
                        print("Reading aligned 8 bytes is ok")
                    else:
                        print("Check (rip = ", hex(rip), ", dest =", dest, ", len =", length / 8, "bytes)")
                        print("Reading unaligned 8 bytes is insecure")

                        state.enclave.print_state()
                        state.enclave.print_call_stack()
                        state.enclave.print_trace()
                        print("Regs:")
                        print(" - %rax = ", state.regs.rax)
                        print(" - %rbx = ", state.regs.rbx)
                        print(" - %rcx = ", state.regs.rcx, " (arg3)")
                        print(" - %rdx = ", state.regs.rdx, " (arg2)")
                        print(" - %rsi = ", state.regs.rsi, " (arg1)")
                        print(" - %rdi = ", state.regs.rdi, " (arg0)")
                        print(" - %r8  = ", state.regs.r8,  " (arg4)")
                        print(" - %r9  = ", state.regs.r9,  " (arg5)")
                        print(" - %r10 = ", state.regs.r10)
                        print(" - %r11 = ", state.regs.r11)
                        print(" - %r12 = ", state.regs.r12)
                        print(" - %r13 = ", state.regs.r13)
                        print(" - %r14 = ", state.regs.r14)
                        print(" - %r15 = ", state.regs.r15)
                        print(" - %rbp = ", state.regs.rbp)
                        print(" - %rsp = ", state.regs.rsp)
                        print(" - %rip = ", state.regs.rip)
                        exit(-3)

                else:
                    print("Trying to insecurely access userspace")
                    exit(-2)


        print("Verifying copy_from_userspace implementation...")
        # Setting up call site
        end = 0x0
        state = self.call_state(
                self.copy_from_userspace,
                ret_addr=end,
                prototype="void copy_from_userspace(uint8_t const *src, uint8_t *dst, size_t len)")
        state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))

        image_base = self.image_base
        enclave_size = state.memory.load(self.enclave_size, 8)
        #state.regs.rsp = state.solver.BVS("rsp", 64)
        #stack_base = claripy.BVS("stack_base", 64)
        #state.solver.add(stack_base == state.regs.rsp)
        #state.solver.add(0x100000 <= enclave_size)
        #state.regs.rsp = 0xb00000000
        self.stack_base = state.solver.eval(state.regs.rsp)
        print("stack base =", hex(self.stack_base))

        # Setting up break points
        # See https://docs.angr.io/core-concepts/simulation#caution-about-mem_read-breakpoint
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=lambda s : track_read(s, self.project))


        #cfg = self.project.analyses.CFGFast(function_starts=[self.copy_to_userspace])
        #func = cfg.kb.functions[self.copy_to_userspace]
        #for block in func.blocks:
        #    print("block: ")
        #    block.pp()
            #print(block.insns())
        # https://api.angr.io/angr.html?highlight=function#angr.knowledge_plugins.functions.function.Function.blocks

        # Running the simulation
        sm = self.simulation_manager(state)
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=EnclaveVerification.MAX_STATES)

        # Print results
        print(sm)
        return self.process_result(sm)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        enclave = VerificationCopyFromUserspace(enclave_path)
        if not(enclave.verify()):
            exit(-1)
        else:
            print("SUCCESS")
