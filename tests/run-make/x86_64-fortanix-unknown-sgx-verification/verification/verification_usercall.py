import angr
import sys
import claripy
from enclave_verification import EnclaveVerification

class CopyToUserspace(angr.SimProcedure):
    def run(self):
        print("Simulating copy_to_userspace")

class Usercall(angr.SimProcedure):
    def run(self):
        print("Simulating usercall")

class StringFromBytebuffer(angr.SimProcedure):
    def run(self):
        print("Simulating string_from_bytebuffer")

class VerificationUsercall(EnclaveVerification):
    def __init__(self, enclave_path):
        EnclaveVerification.__init__(self, enclave_path)

    def verify(self, usercall_name, prototype, environment=None):
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
                state.regs.gs < pow(2, 64) - EnclaveVerification.GS_SEGMENT_SIZE,
                claripy.Not(
                    claripy.And(
                        state.regs.gs <= dest,
                        dest < (state.regs.gs + EnclaveVerification.GS_SEGMENT_SIZE)
                    )
                ),
                )))
            print("is on gs segment:", is_on_gs)
            return is_on_gs

        def track_write(state, sm, p):
            length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
            val = state.inspect.mem_write_expr
            dest = state.inspect.mem_write_address
            rip = state.solver.eval(state.regs.rip)

            # We're not enforcing that the stack is part of the enclave for now. We just assume it's relative to the rsp
            if not(is_enclave_range(state, dest, length) or is_stack_range(state, dest, length) or is_gs_segment(state, dest, length)):
                print("Writing outside of enclave at", hex(rip), "(dest =", dest, ", len =", int(length / 8), "bytes)")
                sm.stashes[EnclaveVerification.WRITE_VIOLATION].append(state.copy())
            else:
                print("Writing within enclave at", hex(rip), "(dest =", dest, ", len =", int(length / 8), "bytes)")
        print("Verifying", usercall_name, "implementation...")

        # hooking symbols
        self.project.hook_symbol(self.copy_to_userspace, CopyToUserspace())
        self.project.hook_symbol(self.usercall, Usercall())
        self.project.hook_symbol(self.string_from_bytebuffer, StringFromBytebuffer())

        # Setting up call site
        usercall = self.project.loader.find_symbol(usercall_name).rebased_addr
        end = 0x0
        state = self.call_state(
                usercall,
                ret_addr=end,
                prototype=prototype)

        # Setting up environment
        if environment == None:
            state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
            self.stack_base = state.solver.eval(state.regs.rsp)
            state.regs.gs = claripy.BVS("gs", 64)
        else:
            state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
            self.stack_base = state.solver.eval(state.regs.rsp)
            state.regs.gs = claripy.BVS("gs", 64)
            environment(state)

        # Setting up break points
        sm = self.simulation_manager(state)
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s : track_write(s, sm, self.project))

        # Running the simulation
        sm = sm.explore(find=lambda s : should_reach(s, end), avoid=should_avoid, num_find=EnclaveVerification.MAX_STATES)

        # Print results
        print(sm)
        return self.process_result(sm)

def environment_accept_stream(state):
    # The `accept_stream` assumes a pointer as first argument. This needs to be within the enclave. We mimick
    # this by placing it on the gs segment
    state.regs.rdi = state.regs.gs

usercalls = {
        "insecure_time" : "uint64_t insecure_time(void)",
        "raw_read" : "uint64_t read(uint64_t fd, uint8_t *buf, uint64_t len)",
        "raw_read_alloc" : "uint64_t read_alloc(uint64_t fd, uint8_t *buf, uint64_t len)",
        "read_alloc" : "uint64_t *read_alloc(uint64_t fd)",
        "raw_accept_stream" : "uint64_t raw_accept_stream(uint64_t fd, uint8_t *local, uint8_t *peer)",
        "raw_alloc" : "uint64_t *raw_alloc(uint64_t size, uint64_t alignment)",
        "alloc" : "uint64_t *alloc(uint64_t size, uint64_t alignment)",
        "raw_async_queues" : "uint64_t *raw_async_queues(uint64_t *usercall_queue, uint64_t *return_queue)",
        "raw_bind_stream" : "uint64_t *raw_bind_stream(uint8_t *addr, uint64_t len, uint64_t *local_addr)",
        "bind_stream" : "uint64_t *raw_bind_stream(uint8_t *addr)",
        "raw_close" : "void close(uint64_t fd)",
        "close" : "void close(uint64_t fd)",
        "raw_connect_stream" : "void connect_stream(uint8_t *addr, uint64_t len, uint64_t *local_addr, uint64_t *peer_addr)",
        "connect_stream" : "void connect_stream(uint8_t *addr)",
        "exit" : "void exit(int v)",
        "raw_flush" : "void flush(uint64_t fd)",
        "flush" : "void flush(uint64_t fd)",
        "raw_free" : "void free(uint64_t *ptr, uint64_t size, uint64_t alignment)",
        "raw_launch_thread" : "void launch_thread()",
        "launch_thread" : "void launch_thread()",
        "raw_send" : "void send(uint64_t event_set, uint8_t* tcs)",
        "send" : "void send(uint64_t event_set, uint8_t* tcs)",
        "raw_wait" : "void wait(uint64_t event, uint64_t timeout)",
        "wait" : "void wait(uint64_t event, uint64_t timeout)",
        "raw_write" : "uint64_t write(uint64_t fd, uint8_t *buf, uint64_t len)",
    }

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf> <usercall name>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]
        usercall: str = sys.argv[2]
        env = None
        prototype = None

        if usercall in usercalls:
            prototype = usercalls[usercall]
            env = None
        else:
            if usercall == "accept_stream":
                prototype = "uint64_t *accept_stream(uint64_t fd)"
                env = environment_accept_stream 
            else:
                print("Unknown usercall:", usercall, "select one of: ", usercalls.keys())
                exit(-1)

        enclave = VerificationUsercall(enclave_path)
        if not(enclave.verify(usercall, prototype, env)):
            print("FAILURE")
            exit(-1)
        else:
            print("SUCCESS")

