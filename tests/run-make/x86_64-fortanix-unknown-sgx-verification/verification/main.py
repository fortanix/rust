# https://docs.angr.io/core-concepts/toplevel

import archinfo
import angr
import claripy
import hooker
import sys
import pyvex

from angr.calling_conventions import SimCCSystemVAMD64

from enclave_state import EnclaveState
from breakpoints import Breakpoints
from layout import Layout

class CopyToUserspace(angr.SimProcedure):
    def run(self):
        print("Simulating copy_to_userspace")

class Usercall(angr.SimProcedure):
    def run(self):
        print("Simulating usercall")

class Enclave:
    MAX_STATES = 25
    GS_SEGMENT_SIZE = 0x1000

    def __init__(self, enclave_path):
        self.enclave = enclave_path
        project = angr.Project(enclave_path, load_options={'auto_load_libs': False})

        # Hook and simulate specific instructions that are unknown to angr
        project = hooker.Hooker().setup(project)
        self.project = project
        self.locate_symbols()

    def locate_symbols(self):
        self.sgx_entry = self.project.loader.find_symbol("sgx_entry").rebased_addr
        self.entry = self.project.loader.find_symbol("entry").rebased_addr
        self.copy_to_userspace = self.project.loader.find_symbol("_ZN3std3sys3sgx3abi9usercalls5alloc17copy_to_userspace17h1c95d92d7bcf993aE").rebased_addr
        self.panic = self.project.loader.find_symbol("_ZN4core9panicking5panic17h5eea59d0f074ef09E").rebased_addr
        self.abort_internal = self.project.loader.find_symbol("_ZN3std3sys3sgx14abort_internal17h2ac111d0112dbbb2E").rebased_addr
        self.enclave_size = self.project.loader.find_symbol("ENCLAVE_SIZE").rebased_addr
        self.image_base = self.project.loader.find_symbol("IMAGE_BASE").rebased_addr

        print("Located symbols:")
        print("  sgx_entry:         " + hex(self.sgx_entry))
        print("  entry:             " + hex(self.entry))
        print("  image_base:        " + hex(self.image_base))
        print("  copy_to_userspace: " + hex(self.copy_to_userspace))
        print("  panic:             " + hex(self.panic))

    def verify_abi(self):
        self.verify_entry()

    def verify_entry(self):
        print("Specifying initial state")
        # By default angr concretizes symbolic addresses when they are used as the target of a write.
        # https://docs.angr.io/advanced-topics/concretization_strategies
        entry_state = self.project.factory.blank_state(addr=self.sgx_entry, add_options={"SYMBOLIC_WRITE_ADDRESSES"})
        entry_state.regs.rsp = entry_state.solver.BVS("rsp", 64)
        entry_state.regs.rdi = entry_state.solver.BVS("rdi", 64)

        print("Verifying...")
        self.project.factory.block(self.sgx_entry).pp()
        print("...")

        print("Executing symbolically")
        assert entry_state.solver.eval(entry_state.regs.rip) == self.sgx_entry
        sm = self.project.factory.simulation_manager(entry_state)
        print(sm.explore(find=self.entry))

        # Inspect results
        # TODO 2 unconstrained path? Need to avoid certain paths (e.g., usercall_ret, ...) but this requires making the symbol global. Alternatively, the initial state can be changed to force testing (non) usercall returns
        if len(sm.found) > 0:
            assert not(sm.found[0].solver.satisfiable(extra_constraints=[sm.found[0].registers.load("rip") != self.entry]))

            if sm.found[0].solver.satisfiable(extra_constraints=[sm.found[0].registers.load("rdi") != entry_state.regs.rdi]):
                print("satisfiable, counter example found!")
            else:
                print("not satisfiable: ok, this constraint always holds")
        else:
            print("errored: ", sm.errored[0])

    def call_state(self, addr, *args, **kwargs):
        arch = archinfo.arch_from_id("amd64")
        state = self.project.factory.call_state(
                addr,
                *args,
                cc=SimCCSystemVAMD64(arch),
                prototype=kwargs["prototype"],
                ret_addr=kwargs["ret_addr"],
                add_options={"SYMBOLIC_WRITE_ADDRESSES", "SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"})
        state.register_plugin('enclave', EnclaveState(self.project))
        state.enclave.init_trace_and_stack()

        # Fake enclave state
        #state.memory.store(self.enclave_size, state.solver.BVV(0x100000, 64))
        #state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))

        return state

    def simulation_manager(self, state):
        sm = self.project.factory.simulation_manager(state)
        self.project, sm = Breakpoints().setup(self.project, sm, Layout())
        return sm

    def print_states(states, name):
        print("=[", len(states), name, " states ]=")
        for idx_state in range(0, len(states)):
            state = states[idx_state]
            print("[", name, "state ", idx_state + 1, "/", len(states), "]")
            state.enclave.print_state()
            state.enclave.print_call_stack()
            state.enclave.print_trace()
            print("")

    def print_errored_states(records):
        print("=[", len(records), "errored states ]=")
        for idx_state in range(0, len(records)):
            state = records[idx_state].state
            print("[errored state ", idx_state + 1, "/", len(records), "]")
            print("Error: ", records[idx_state].error)
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
            #print(" - %d   = ", state.regs.dflag)
            #print(" - %e   = ", state.regs.eflags)
            #print(" - %r   = ", state.regs.get("rflags"))
            print("")

    def process_result(sm):
        if len(sm.found) == Enclave.MAX_STATES:
            print("Error: Maximum number of states reached:", Enclave.MAX_STATES)
            return False
        elif len(sm.errored) != 0:
            print("Error: Some states reached an error")
            Enclave.print_states(sm.found, "Found")
            Enclave.print_errored_states(sm.errored)
            return False
        elif len(sm.unconstrained) != 0:
            print("Error: Some states reached an unconstrained state")
            Enclave.print_states(sm.found, "Found")
            Enclave.print_errored_states(sm.errored)
            return False
        else:
            Enclave.print_states(sm.found, "Found")
            Enclave.print_errored_states(sm.errored)
            return True

    def verify_image_base(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        print("Verifying image_base implementation...")
        end = 0x0
        state = self.call_state(self.project.loader.find_symbol("get_image_base").rebased_addr, ret_addr=end, prototype="uint64_t get_image_base(void)")

        sm = self.simulation_manager(state)
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=Enclave.MAX_STATES)

        if not(Enclave.process_result(sm)):
            return False
        else:
            if len(sm.found) != 1:
                print("Error: Unexpected amount of found states")
                return False
            else:
                assert(sm.found[0].solver.eval(sm.found[0].regs.rax == self.image_base))
                return True

    def verify_is_enclave_range(self):
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
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=Enclave.MAX_STATES)

        if not(Enclave.process_result(sm)):
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

    def verify_copy_to_userspace(self):
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
            # Checks whether we're dealing with this code block:
            #   22afc:    8c 1f            mov    %ds,(%rdi)
            #   22afe:    0f 00 2f         verw   (%rdi)
            #   22b01:    0f ae e8         lfence
            #   22b04:    88 01            mov    %al,(%rcx)   # <- rip points to this location
            #   22b06:    0f ae f0         mfence
            #   22b09:    0f ae e8         lfence
            opt1 = read_instr(state, rip - 8, 2) == b'\x8c\x1f' and read_instr(state, rip - 6, 3) == b'\x0f\x00\x2f' and read_instr(state, rip - 3, 3) == b'\x0f\xae\xe8' and read_instr(state, rip, 2) == b'\x88\x01' and read_instr(state, rip + 2, 3) == b'\x0f\xae\xf0' and read_instr(state, rip + 5, 3) == b'\x0f\xae\xe8'

            # Checks whether we're dealing with this code block:
            #   22b6c:    41 8c 1a         mov    %ds,(%r10)
            #   22b6f:    41 0f 00 2a      verw   (%r10)
            #   22b73:    0f ae e8         lfence
            #   22b76:    88 0e            mov    %cl,(%rsi)
            #   22b78:    0f ae f0         mfence
            #   22b7b:    0f ae e8         lfence
            opt2 = read_instr(state, rip - 10, 3) == b'\x41\x8c\x1a' and read_instr(state, rip - 7, 4) == b'\x41\x0f\x00\x2a' and read_instr(state, rip - 3, 3) == b'\x0f\xae\xe8' and read_instr(state, rip, 2) == b'\x88\x0e' and read_instr(state, rip + 2, 3) == b'\x0f\xae\xf0' and read_instr(state, rip + 5, 3) == b'\x0f\xae\xe8'

            # Checks whether we're dealing with this code block:
            #   22bdc:    8c 1e            mov    %ds,(%rsi)
            #   22bde:    0f 00 2e         verw   (%rsi)
            #   22be1:    0f ae e8         lfence
            #   22be4:    88 01            mov    %al,(%rcx)
            #   22be6:    0f ae f0         mfence
            #   22be9:    0f ae e8         lfence
            opt3 = read_instr(state, rip - 8, 2) == b'\x8c\x1e' and read_instr(state, rip - 6, 3) == b'\x0f\x00\x2e' and read_instr(state, rip - 3, 3) == b'\x0f\xae\xe8' and read_instr(state, rip, 2) == b'\x88\x01' and read_instr(state, rip + 2, 3) == b'\x0f\xae\xf0' and read_instr(state, rip + 5, 3) == b'\x0f\xae\xe8'

            return opt1 or opt2 or opt3


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
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=Enclave.MAX_STATES)

        # Print results
        print(sm)
        return Enclave.process_result(sm)

    def verify_usercall(self, usercall_name, prototype):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic) or state.solver.eval(state.regs.rip == self.abort_internal)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        def is_enclave_range(state, p, length):
            image_base = self.image_base
            enclave_size = state.memory.load(self.enclave_size, 8)

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

        def is_gs_segment(state, dest, length):
            print("Check write on gs segment")
            print("gs segment base:", state.regs.gs)
            print("write dest:", dest, "len:", length)
            is_on_gs = not(state.solver.satisfiable(extra_constraints=(
                state.regs.gs < pow(2, 64) - Enclave.GS_SEGMENT_SIZE,
                claripy.Not(
                    claripy.And(
                        state.regs.gs <= dest,
                        dest < (state.regs.gs + Enclave.GS_SEGMENT_SIZE)
                    )
                ),
                )))
            print("is on gs segment:", is_on_gs)
            return is_on_gs

        def track_write(state, p):
            length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
            val = state.inspect.mem_write_expr
            dest = state.inspect.mem_write_address
            rip = state.solver.eval(state.regs.rip)

            # We're not enforcing that the stack is part of the enclave for now. We just assume it's relative to the rsp
            if not(is_enclave_range(state, dest, length) or is_stack_range(state, dest, length) or is_gs_segment(state, dest, length)):
                print("Writing outside of enclave at", hex(rip), "(dest =", dest, ", len =", int(length / 8), "bytes)")
                exit(-2)
            else:
                print("Writing within enclave at", hex(rip), "(dest =", dest, ", len =", int(length / 8), "bytes)")
        print("Verifying", usercall_name, "implementation...")

        # hooking symbols
        self.project.hook_symbol('_ZN3std3sys3sgx3abi9usercalls5alloc17copy_to_userspace17h1c95d92d7bcf993aE', CopyToUserspace())
        self.project.hook_symbol('usercall', Usercall())

        # Setting up call site
        usercall = self.project.loader.find_symbol(usercall_name).rebased_addr
        end = 0x0
        state = self.call_state(
                usercall,
                ret_addr=end,
                prototype=prototype)

        # Setting up environment
        state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
        self.stack_base = state.solver.eval(state.regs.rsp)
        state.regs.gs = claripy.BVS("gs", 64)

        # Setting up break points
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s : track_write(s, self.project))

        # Running the simulation
        sm = self.simulation_manager(state)
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=Enclave.MAX_STATES)

        # Print results
        print(sm)
        return Enclave.process_result(sm)

    def verify(self, verification_pass):
        if verification_pass == "image_base":
            return self.verify_image_base()
        elif verification_pass == "is_enclave_range":
            return self.verify_is_enclave_range()
        elif verification_pass == "copy_to_userspace":
            return self.verify_copy_to_userspace()
        elif verification_pass == "insecure_time":
            return self.verify_usercall("insecure_time", "uint64_t insecure_time(void)")
        elif verification_pass == "raw_read":
            return self.verify_usercall("raw_read", "uint64_t read(uint64_t fd, uint8_t *buf, uint64_t len)")
        elif verification_pass == "raw_read_alloc":
            return self.verify_usercall("raw_read_alloc", "uint64_t read_alloc(uint64_t fd, uint8_t *buf, uint64_t len)")
        elif verification_pass == "raw_accept_stream":
            return self.verify_usercall("raw_accept_stream", "uint64_t raw_accept_stream(uint64_t fd, uint8_t *local, uint8_t *peer)")
        elif verification_pass == "raw_alloc":
            return self.verify_usercall("raw_alloc", "uint64_t *raw_alloc(uint64_t size, uint64_t alignment)")
        elif verification_pass == "raw_async_queues":
            return self.verify_usercall("raw_async_queues", "uint64_t *raw_async_queues(uint64_t *usercall_queue, uint64_t *return_queue)")
        elif verification_pass == "raw_bind_stream":
            return self.verify_usercall("raw_bind_stream", "uint64_t *raw_bind_stream(uint8_t *addr, uint64_t len, uint64_t *local_addr)")
        elif verification_pass == "raw_close":
            return self.verify_usercall("raw_close", "void close(uint64_t fd)")
        elif verification_pass == "raw_connect_stream":
            return self.verify_usercall("raw_connect_stream", "void connect_stream(uint8_t *addr, uint64_t len, uint64_t *local_addr, uint64_t *peer_addr)")
        elif verification_pass == "raw_exit":
            return self.verify_usercall("raw_exit", "void exit(int v)")
        elif verification_pass == "raw_flush":
            return self.verify_usercall("raw_flush", "void flush(uint64_t fd)")
        elif verification_pass == "raw_free":
            return self.verify_usercall("raw_free", "void free(uint64_t *ptr, uint64_t size, uint64_t alignment)")
        elif verification_pass == "raw_launch_thread":
            return self.verify_usercall("raw_launch_thread", "void launch_thread()")
        elif verification_pass == "raw_send":
            return self.verify_usercall("raw_send", "void send(uint64_t event_set, uint8_t* tcs)")
        elif verification_pass == "raw_wait":
            return self.verify_usercall("raw_wait", "void wait(uint64_t event, uint64_t* timeout)")
        elif verification_pass == "raw_write":
            return self.verify_usercall("raw_write", "uint64_t write(uint64_t fd, uint8_t *buf, uint64_t len)")
        else:
            print("Verification pass not recognized:", verification_pass)
            return False

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf> <verification_pass>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]
        verification_pass: str = sys.argv[2]

        enclave = Enclave(enclave_path)
        if not(enclave.verify(verification_pass)):
            exit(-1)
        else:
            print("SUCCESS")
