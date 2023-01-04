import angr
import sys
import claripy
from enclave_verification import EnclaveVerification

class CopyToUserspace(angr.SimProcedure):
    def run(self):
        print("Simulating copy_to_userspace")

class Usercall(angr.SimProcedure):
    def run(self):
        print("Simulating usercall enclave exit")

class StringFromBytebuffer(angr.SimProcedure):
    def run(self):
        print("Simulating string_from_bytebuffer")

class Rdrand(angr.SimProcedure):
    def run(self):
        print("Simulating rdrand")

class VerificationUsercall(EnclaveVerification):
    def __init__(self, enclave_path, name):
        EnclaveVerification.__init__(self, enclave_path, "VerificationUsercall::" + name)

    def verify(self, usercall_name, prototype, environment=None):
        def should_avoid(state):
            return state.solver.eval(state.regs.rip == self.panic) or state.solver.eval(state.regs.rip == self.abort_internal)

        def should_reach(state, end):
            return state.solver.eval(state.regs.rip == end)

        def track_write(state, sm, p):
            length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None else len(state.inspect.mem_write_expr)
            val = state.inspect.mem_write_expr
            dest = state.inspect.mem_write_address
            rip = state.solver.eval(state.regs.rip)
            self.logger.debug(hex(rip) + ": write " + str(int(length / 8)) + " bytes to " + str(dest))

            if self.is_enclave_space(state, dest, length):
                self.logger.debug("    - in enclave: ok" )
            elif self.is_on_stack(state, dest, length):
                self.logger.debug("    - on stack: ok" )
            elif self.is_on_gs_segment(state, dest, length):
                self.logger.debug("    - on gs segment: ok" )
            else:
                self.logger.error(hex(rip) + ": write " + str(int(length / 8)) + " bytes to " + str(dest))
                self.logger.error("    - in enclave: no" )
                self.logger.error("    - on stack: no" )
                self.logger.debug("    - on gs segment: no" )
                self.log_state(state)
                sm.stashes[EnclaveVerification.WRITE_VIOLATION].append(state.copy())

        # hooking symbols
        self.project.hook_symbol(self.copy_to_userspace, CopyToUserspace())
        self.project.hook_symbol(self.usercall, Usercall())
        self.project.hook_symbol(self.string_from_bytebuffer, StringFromBytebuffer())
        self.project.hook_symbol(self.find_symbol_matching(".*std.sys.sgx.rand.rdrand.*").rebased_addr, Rdrand())

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
            elif usercall == "wait":
                prototype = "uint64_t *wait(uint64_t event, uint64_t timeout)",
                env = environment_wait
            else:
                print("Unknown usercall:", usercall, "select one of: ", usercalls.keys())
                exit(-1)

        print("Verifying", usercall, "implementation...")
        if not(VerificationUsercall(enclave_path, usercall).verify(usercall, prototype, env)):
            print("Failed")
            exit(-1)
        else:
            print("Succeeded")

