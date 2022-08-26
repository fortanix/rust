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
from enclave_verification import EnclaveVerification
from verification_image_base import VerificationImageBase

# class CopyToUserspace(angr.SimProcedure):
#     def run(self):
#         print("Simulating copy_to_userspace")
# 
# class Usercall(angr.SimProcedure):
#     def run(self):
#         print("Simulating usercall")
# 
# class StringFromBytebuffer(angr.SimProcedure):
#     def run(self):
#         print("Simulating string_from_bytebuffer")
# 
# INSTR_LFENCE = b'\x0f\xae\xe8'
# INSTR_MFENCE = b'\x0f\xae\xf0'
# 
# class Enclave:
#     MAX_STATES = 25
#     GS_SEGMENT_SIZE = 0x1000
# 
#     def __init__(self, enclave_path):
#         self.enclave = enclave_path
#         project = angr.Project(enclave_path, load_options={'auto_load_libs': False})
# 
#         # Hook and simulate specific instructions that are unknown to angr
#         project = hooker.Hooker().setup(project)
#         self.project = project
#         self.locate_symbols()
# 
#     def locate_symbols(self):
#         def find_symbol_matching(name):
#             symbols = list(filter(lambda s : name in s.name, self.project.loader.symbols))
#             if len(symbols) != 1:
#                 print("Multiple symbols matching\"", name, "\"found:", symbols)
#                 exit(-1)
#             else:
#                 return symbols[0]
# 
#         self.sgx_entry = self.project.loader.find_symbol("sgx_entry").rebased_addr
#         self.entry = self.project.loader.find_symbol("entry").rebased_addr
#         self.copy_to_userspace = find_symbol_matching("copy_to_userspace").rebased_addr
#         self.panic = find_symbol_matching("panicking5panic").rebased_addr
#         self.abort_internal = find_symbol_matching("abort_internal").rebased_addr
#         self.enclave_size = self.project.loader.find_symbol("ENCLAVE_SIZE").rebased_addr
#         self.image_base = self.project.loader.find_symbol("IMAGE_BASE").rebased_addr
#         self.string_from_bytebuffer = find_symbol_matching("string_from_bytebuffer").rebased_addr
#         self.usercall = self.project.loader.find_symbol("usercall").rebased_addr
# 
#         print("Located symbols:")
#         print("  sgx_entry:              " + hex(self.sgx_entry))
#         print("  entry:                  " + hex(self.entry))
#         print("  image_base:             " + hex(self.image_base))
#         print("  copy_to_userspace:      " + hex(self.copy_to_userspace))
#         print("  panic:                  " + hex(self.panic))
#         print("  string_from_bytebuffer: " + hex(self.string_from_bytebuffer))
# 
#     def verify_abi(self):
#         self.verify_entry()
# 
#     def verify_entry(self):
#         print("Specifying initial state")
#         # By default angr concretizes symbolic addresses when they are used as the target of a write.
#         # https://docs.angr.io/advanced-topics/concretization_strategies
#         entry_state = self.project.factory.blank_state(addr=self.sgx_entry, add_options={"SYMBOLIC_WRITE_ADDRESSES"})
#         entry_state.regs.rsp = entry_state.solver.BVS("rsp", 64)
#         entry_state.regs.rdi = entry_state.solver.BVS("rdi", 64)
# 
#         print("Verifying...")
#         self.project.factory.block(self.sgx_entry).pp()
#         print("...")
# 
#         print("Executing symbolically")
#         assert entry_state.solver.eval(entry_state.regs.rip) == self.sgx_entry
#         sm = self.project.factory.simulation_manager(entry_state)
#         print(sm.explore(find=self.entry))
# 
#         # Inspect results
#         # TODO 2 unconstrained path? Need to avoid certain paths (e.g., usercall_ret, ...) but this requires making the symbol global. Alternatively, the initial state can be changed to force testing (non) usercall returns
#         if len(sm.found) > 0:
#             assert not(sm.found[0].solver.satisfiable(extra_constraints=[sm.found[0].registers.load("rip") != self.entry]))
# 
#             if sm.found[0].solver.satisfiable(extra_constraints=[sm.found[0].registers.load("rdi") != entry_state.regs.rdi]):
#                 print("satisfiable, counter example found!")
#             else:
#                 print("not satisfiable: ok, this constraint always holds")
#         else:
#             print("errored: ", sm.errored[0])
# 
#     def call_state(self, addr, *args, **kwargs):
#         arch = archinfo.arch_from_id("amd64")
#         state = self.project.factory.call_state(
#                 addr,
#                 *args,
#                 cc=SimCCSystemVAMD64(arch),
#                 prototype=kwargs["prototype"],
#                 ret_addr=kwargs["ret_addr"],
#                 add_options={"SYMBOLIC_WRITE_ADDRESSES", "SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"})
#         state.register_plugin('enclave', EnclaveState(self.project))
#         state.enclave.init_trace_and_stack()
# 
#         # Fake enclave state
#         #state.memory.store(self.enclave_size, state.solver.BVV(0x100000, 64))
#         #state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
# 
#         return state
# 
#     def simulation_manager(self, state):
#         sm = self.project.factory.simulation_manager(state)
#         self.project, sm = Breakpoints().setup(self.project, sm, Layout())
#         return sm
# 
#     def print_states(states, name):
#         print("=[", len(states), name, " states ]=")
#         for idx_state in range(0, len(states)):
#             state = states[idx_state]
#             print("[", name, "state ", idx_state + 1, "/", len(states), "]")
#             state.enclave.print_state()
#             state.enclave.print_call_stack()
#             state.enclave.print_trace()
#             print("")
# 
#     def print_errored_states(records):
#         print("=[", len(records), "errored states ]=")
#         for idx_state in range(0, len(records)):
#             state = records[idx_state].state
#             print("[errored state ", idx_state + 1, "/", len(records), "]")
#             print("Error: ", records[idx_state].error)
#             print("Regs:")
#             print(" - %rax = ", state.regs.rax)
#             print(" - %rbx = ", state.regs.rbx)
#             print(" - %rcx = ", state.regs.rcx, " (arg3)")
#             print(" - %rdx = ", state.regs.rdx, " (arg2)")
#             print(" - %rsi = ", state.regs.rsi, " (arg1)")
#             print(" - %rdi = ", state.regs.rdi, " (arg0)")
#             print(" - %r8  = ", state.regs.r8,  " (arg4)")
#             print(" - %r9  = ", state.regs.r9,  " (arg5)")
#             print(" - %r10 = ", state.regs.r10)
#             print(" - %r11 = ", state.regs.r11)
#             print(" - %r12 = ", state.regs.r12)
#             print(" - %r13 = ", state.regs.r13)
#             print(" - %r14 = ", state.regs.r14)
#             print(" - %r15 = ", state.regs.r15)
#             print(" - %rbp = ", state.regs.rbp)
#             print(" - %rsp = ", state.regs.rsp)
#             print(" - %rip = ", state.regs.rip)
#             #print(" - %d   = ", state.regs.dflag)
#             #print(" - %e   = ", state.regs.eflags)
#             #print(" - %r   = ", state.regs.get("rflags"))
#             print("")
# 
#     def process_result(sm):
#         if len(sm.found) == Enclave.MAX_STATES:
#             print("Error: Maximum number of states reached:", Enclave.MAX_STATES)
#             return False
#         elif len(sm.errored) != 0:
#             print("Error: Some states reached an error")
#             Enclave.print_states(sm.found, "Found")
#             Enclave.print_errored_states(sm.errored)
#             return False
#         elif len(sm.unconstrained) != 0:
#             print("Error: Some states reached an unconstrained state")
#             Enclave.print_states(sm.found, "Found")
#             Enclave.print_errored_states(sm.errored)
#             return False
#         else:
#             Enclave.print_states(sm.found, "Found")
#             Enclave.print_errored_states(sm.errored)
#             return True
# 
 
# 
# 
#     def environment_accept_stream(self, state):
#         state.memory.store(self.enclave_size, state.solver.BVS("enlave_size", 64))
#         self.stack_base = state.solver.eval(state.regs.rsp)
#         state.regs.gs = claripy.BVS("gs", 64)
# 
#         # The `accept_stream` assumes a pointer as first argument. This needs to be within the enclave. We mimick
#         # this by placing it on the gs segment
#         state.regs.rdi = state.regs.gs
# 

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./" + sys.argv[0] + " <enclave.elf> <verification_pass>")
        exit(-1)
    else:
        enclave_path: str = sys.argv[1]
        verification_pass: str = sys.argv[2]

        enclave = VerificationImageBase(enclave_path)
        if not(enclave.verify()):
            exit(-1)
        else:
            print("SUCCESS")
