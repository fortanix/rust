import angr
import claripy
import sys
from enclave_verification import EnclaveVerification

INSTR_LFENCE = b'\x0f\xae\xe8'
INSTR_MFENCE = b'\x0f\xae\xf0'

class VerificationCopyToUserspace(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path)

    def verify(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        def is_enclave_range(state, p, length):
            image_base = self.image_base
            enclave_size = state.memory.load(self.enclave_size, 8)
            #print("enclave_size =", enclave_size)
            #print("image_size =", hex(image_base))
            
            ptr = claripy.BVS("ptr", 64)

            # [p; p + length[ may be in enclave range when:
            # `ptr in [p; p + length[`
            # and `ptr in [image_base; image_base + enclave_size[`
            return state.solver.satisfiable(extra_constraints=(
                p <= ptr,
                ptr < p + length,
                self.image_base <= ptr,
                ptr < (self.image_base + enclave_size),
                p + enclave_size < pow(2, 64)
                ))

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
            #print("is_stack_range: dest:", dest, "len:", length)
            #print("is_stack_range: stack base:", hex(self.stack_base))
            return not(state.solver.satisfiable(extra_constraints=(
                dest & 0x7 != 0,
                )))

        def read_instr(state, rip, length):
            instr = state.memory.load(rip, length)
            instr = state.solver.eval(instr)
            instr = instr.to_bytes(length, 'big')
            #print("instr =", instr, "(type =", type(instr), ")")
            return instr

        def is_safe_userspace_write(state, rip):
            def is_mov_prologue(state, rip):
                def test_mov_prologue(state, rip, instrs):
                    return read_instr(state, rip - len(instrs), len(instrs)) == instrs

                # mov    %ds,(%rax)
                MOV_DS_TO_PTR_RAX = b'\x8c\x18'

                # mov    %ds,(%rbx)
                MOV_DS_TO_PTR_RBX = b'\x8c\x1b'

                # mov    %ds,(%rcx)
                MOV_DS_TO_PTR_RCX = b'\x8c\x19'

                # mov    %ds,(%rdx)
                MOV_DS_TO_PTR_RDX = b'\x8c\x1a'

                # mov    %ds,(%rsi)
                MOV_DS_TO_PTR_RSI = b'\x8c\x1e'

                # mov    %ds,(%rdi)
                MOV_DS_TO_PTR_RDI = b'\x8c\x1f'

                # mov    %ds,(%r8)
                MOV_DS_TO_PTR_R8 = b'\x41\x8c\x18'

                # mov    %ds,(%r9)
                MOV_DS_TO_PTR_R9 = b'\x41\x8c\x19'

                # mov    %ds,(%r10)
                MOV_DS_TO_PTR_R10 = b'\x41\x8c\x1a'

                # mov    %ds,(%r11)
                MOV_DS_TO_PTR_R11 = b'\x41\x8c\x1b'

                # mov    %ds,(%r12)
                MOV_DS_TO_PTR_R12 = b'\x41\x8c\x1c\x24'

                # mov    %ds,(%r13)
                MOV_DS_TO_PTR_R13 = b'\x41\x8c\x5d\x00'

                # mov    %ds,(%r14)
                MOV_DS_TO_PTR_R14 = b'\x41\x8c\x1e'

                # mov    %ds,(%r15)
                MOV_DS_TO_PTR_R15 = b'\x41\x8c\x1f'


                # 0f 00 28             	verw   (%rax)
                VERW_RAX = b'\x0f\x00\x28'

                # 0f 00 2b             	verw   (%rbx)
                VERW_RBX = b'\x0f\x00\x2b'

                # 0f 00 29             	verw   (%rcx)
                VERW_RCX = b'\x0f\x00\x29'

                # 0f 00 2a             	verw   (%rdx)
                VERW_RDX = b'\x0f\x00\x2a'

                # 0f 00 2e             	verw   (%rsi)
                VERW_RSI = b'\x0f\x00\x2e'

                # 0f 00 2f             	verw   (%rdi)
                VERW_RDI = b'\x0f\x00\x2f'

                # 41 0f 00 28          	verw   (%r8)
                VERW_R8 = b'\x41\x0f\x00\x28'

                # 41 0f 00 29          	verw   (%r9)
                VERW_R9 = b'\x41\x0f\x00\x29'

                # 41 0f 00 2a          	verw   (%r10)
                VERW_R10 = b'\x41\x0f\x00\x2a'

                # 41 0f 00 2b          	verw   (%r11)
                VERW_R11 = b'\x41\x0f\x00\x2b'

                # 41 0f 00 2c 24       	verw   (%r12)
                VERW_R12 = b'\x41\x0f\x00\x2c'

                # 41 0f 00 6d 00       	verw   0x0(%r13)
                VERW_R13 = b'\x41\x0f\x00\x6d\x00'

                # 41 0f 00 2e          	verw   (%r14)
                VERW_R14 = b'\x41\x0f\x00\x2e'

                # 41 0f 00 2f          	verw   (%r15)
                VERW_R15 = b'\x41\x0f\x00\x2f'

                PROLOGUES = [
                    MOV_DS_TO_PTR_RAX + VERW_RAX + INSTR_LFENCE,
                    MOV_DS_TO_PTR_RBX + VERW_RBX + INSTR_LFENCE,
                    MOV_DS_TO_PTR_RCX + VERW_RCX + INSTR_LFENCE,
                    MOV_DS_TO_PTR_RDX + VERW_RDX + INSTR_LFENCE,
                    MOV_DS_TO_PTR_RSI + VERW_RSI + INSTR_LFENCE,
                    MOV_DS_TO_PTR_RDI + VERW_RDI + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R8  + VERW_R8  + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R9  + VERW_R9  + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R10 + VERW_R10 + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R11 + VERW_R11 + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R12 + VERW_R12 + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R13 + VERW_R13 + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R14 + VERW_R14 + INSTR_LFENCE,
                    MOV_DS_TO_PTR_R15 + VERW_R15 + INSTR_LFENCE]

                for prologue in PROLOGUES:
                    if test_mov_prologue(state, rip, prologue):
                        return True
                return False

            def is_mov_epilogue(state, rip):
                def test_mov_epilogue(state, rip, instrs):
                    return read_instr(state, rip, len(instrs)) == instrs
                return test_mov_epilogue(state, rip, INSTR_MFENCE + INSTR_LFENCE)

            if is_mov_prologue(state, rip):
                print("found prologue!")

            if is_mov_epilogue(state, rip + 2):
                print("found epilogue")

            return is_mov_prologue(state, rip) and is_mov_epilogue(state, rip + 2)


        def track_write(state, p):
            length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
            val = state.inspect.mem_write_expr
            dest = state.inspect.mem_write_address
            rip = state.solver.eval(state.regs.rip)

            # We're not enforcing that the stack is part of the enclave for now. We just assume it's relative to the rsp
            if not(is_enclave_range(state, dest, length)) and not(is_stack_range(state, dest, length)):
                print("Writing outside of enclave at", hex(rip), "(dest =", dest, ", len =", int(length / 8), "bytes)")
                if length == 8:
                    if not is_safe_userspace_write(state, rip):
                        print("Trying to insecurely write", length/8, " bytes to userspace from", hex(rip))
                        exit(-1)
                elif length == 64:
                    if is_aligned64(state, dest):
                        print("Writing aligned 8 bytes is ok")
                    else:
                        print("Check (rip = ", rip, ", dest =", dest, ", len =", length / 8, "bytes)")
                        print("Writing unaligned 8 bytes is insecure")
                        exit(-3)

                else:
                    print("Trying to insecurely access userspace")
                    exit(-2)


        print("Verifying copy_to_userspace implementation...")
        # Setting up call site
        end = 0x0
        state = self.call_state(
                self.copy_to_userspace,
                ret_addr=end,
                prototype="void copy_to_userspace(uint8_t const *src, uint8_t *dst, size_t len)")
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
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s : track_write(s, self.project))


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
        return EnclaveVerification.process_result(sm)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]

        enclave = VerificationCopyToUserspace(enclave_path)
        if not(enclave.verify()):
            exit(-1)
        else:
            print("SUCCESS")
