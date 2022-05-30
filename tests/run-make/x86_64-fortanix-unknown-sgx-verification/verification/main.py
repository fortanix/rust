# https://docs.angr.io/core-concepts/toplevel

import archinfo
import angr
import claripy
import hooker
import sys

from angr.calling_conventions import SimCCSystemVAMD64

from enclave_state import EnclaveState
from breakpoints import Breakpoints
from layout import Layout

class Enclave:
    MAX_STATES = 10

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
        self.copy_to_userspace = self.project.loader.find_symbol("_ZN3std3sys3sgx3abi9usercalls5alloc17copy_to_userspace17hbdab691f05ffa2b8E").rebased_addr
        self.panic = self.project.loader.find_symbol("_ZN4core9panicking5panic17hd2e16c07dcdc0fcdE").rebased_addr
        self.enclave_size = self.project.loader.find_symbol("ENCLAVE_SIZE").rebased_addr
        self.image_base = self.project.loader.find_symbol("IMAGE_BASE").rebased_addr

        print("Located symbols:")
        print("  sgx_entry:         " + hex(self.sgx_entry))
        print("  entry:             " + hex(self.entry))
        print("  image_base:        " + hex(self.image_base))
        print("  copy_to_userspace: " + hex(self.copy_to_userspace))

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
        state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))

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

                # Make a symbolic variable `ptr` with: `ptr in [p; p + len[`
                ptr = claripy.BVS("ptr", 64)
                state.solver.add(p <= ptr)
                state.solver.add(ptr < p + len_)

                # If `ptr in [image_base; image_base + enclave_size[` the result must always be true
                # THIS IS WRONG!!
                #assert(not(state.satisfiable(extra_constraints=(
                #    self.image_base <= ptr,
                #    ptr < self.image_base + self.enclave_size,
                #    result == 0,
                #    ))))

                # If `ptr not in [image_base; image_base + enclave_size[` the result must always be false
                if i == 2:
                    state.solver.add(
                        claripy.Not(
                             claripy.And(
                                 self.image_base <= ptr,
                                 ptr < self.image_base + self.enclave_size
                                 )
                             ))
                    state.solver.add(result != 0)
                    assert(state.satisfiable())

                    res_ptr = state.solver.eval(ptr)
                    state.solver.add(ptr == res_ptr)

                    res_p = state.solver.eval(p)
                    state.solver.add(p == res_p)

                    res_len_ = state.solver.eval(len_)
                    state.solver.add(len_ == res_len_)


                    print("base = ", hex(self.image_base))
                    print("enclave_size = ", hex(self.enclave_size))
                    print("p =", hex(res_p))
                    print("ptr =", hex(res_ptr))
                    print("len =", hex(res_len_))

#                    print("ptr = ", hex(state.solver.eval(ptr, extra_constraints=(
#                        claripy.Not(
#                             claripy.And(
#                                 self.image_base <= ptr,
#                                 ptr < self.image_base + self.enclave_size
#                                 )
#                             ),
#                        result != 0,
#                        ))))
                assert(not(state.satisfiable(extra_constraints=(
                    claripy.Not(
                         claripy.And(
                             self.image_base <= ptr,
                             ptr < self.image_base + self.enclave_size
                             )
                         ),
                    result != 0,
                    ))))

                #assert(state.solver.eval(state.regs.rax == self.image_base))
            return True

    def verify_copy_to_userspace(self):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        def track_write(state, msg):
            length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
            val = state.inspect.mem_write_expr
            dest = state.inspect.mem_write_address
            rip = hex(state.solver.eval(state.regs.rip))
            print(rip, ': Write', val, 'to', dest, " (", length, " bits)", msg)

        print("Verifying copy_to_userspace implementation...")
        # Setting up call site
        end = 0x0
        copy_to_userspace_state = self.call_state(
                self.copy_to_userspace,
                ret_addr=end,
                prototype="void copy_to_userspace(uint8_t const *src, uint8_t *dst, size_t len)")

        # Setting up break points
        copy_to_userspace_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s : track_write(s, "arg"))

        # Running the simulation
        sm = self.simulation_manager(copy_to_userspace_state)
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=Enclave.MAX_STATES)

        # Print results
        print(sm)
        return Enclave.process_result(sm)

    def verify_api(self):
        return (self.verify_image_base() and
            self.verify_is_enclave_range())# and
            #self.verify_copy_to_userspace())

    def verify(self):
        #self.verify_abi()
        return self.verify_api()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]
        enclave = Enclave(enclave_path)
        if not(enclave.verify()):
            exit(-1)
        else:
            print("SUCCESS")
