""" Guardian
    Copyright (C) 2021  The Blockhouse Technology Limited (TBTL)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>."""

import logging, sys
import angr, claripy
import itertools
import collections

log = logging.getLogger(__name__)


class SimEnclu(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self):
        enclu_length_in_bytes = 3
        if self.state.solver.eval(self.state.regs.eax == 0x0):
            log.debug("EREPORT")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x1):
            log.debug("EGETKEY")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x2):
            log.critical("Unexpected EENTER")
            self.exit(1)
        elif self.state.solver.eval(self.state.regs.eax == 0x4):
            log.critical("Unexpected EEXIT")
            self.exit(1)
        else:
            log.critical("Unexpected ENCLU")
            self.exit(1)


class Nop(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')


class Empty(angr.SimProcedure):
    def run(self):
        pass


class UD2(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("UD2 detected! Aborting this branch!")
        log.debug(hex(self.state.addr))
        self.successors.add_successor(self.state, self.state.addr,
                                      self.state.solver.true, 'Ijk_NoHook')
        self.exit(2)


class Rdrand(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.state.regs.flags = 1
        self.successors.add_successor(self.state, self.state.addr + 3,
                                      self.state.solver.true, 'Ijk_Boring')

class Movsq(angr.SimProcedure):
    IS_FUNCTION = False
    def run(self, **kwargs):
        rdi = self.state.registers.load("rdi")
        rsi = self.state.registers.load("rsi")
        # TODO check that req instruction prefix executes correctly
        #self.state.memory.store(0xbeefbeef, self.state.solver.BVV(42, 64))
        self.state.memory.store(rdi, rsi)
        #print("HERE")
        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')


# class TransitionToEnclaveBootstrapperRust(angr.SimProcedure()):
#     IS_FUNCTION = False
#
#     def __init__(self, entry_state, new_state):
#         self.entry_state = entry_state
#         self.new_state = new_state
#
#     def run(self, **kwargs):
#         print("TRANSITIONING")
#         log.debug("######### TRANSITION TO ENCLAVE BOOTSTRAPPER (RUST CODE) ###############")
#
#         # self.project.
#         self.verify_entry_correctness()
#
#         # self.project.
#
#         self.successors.add_successor(self.state, self.state.addr + 0,
#                                       self.state.solver.true, 'Ijk_NoHook')
#
#     def verify_entry_correctness(self):
#         # We check that all the registers have been set correctly
#         assert(claripy.is_true(self.entry_state.registers.load("rsp") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x28].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("rcx") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x30].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("rbp") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x38].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("r12") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x40].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("r13") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x48].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("r14") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x50].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("r15") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x58].uint64_t.resolved))
#         assert(claripy.is_true(self.entry_state.registers.load("rbx") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x68].uint64_t.resolved))
#         # TODO: check all the additional registers as well!
#         custom_vars_dict: {} = { # "rsp": 0xa8, # NOTE: ofcourse not, was using wrong stack before!!!
#             "rax": 0xb0,
#             "rbx": 0xb8,
#             "rcx": 0xc0,
#             "rdx": 0xc8,
#             "rdi": 0xd0,
#             "rsi": 0xd8,
#             "rbp": 0xe0,
#             "r8" : 0xe8,
#             "r9" : 0xf0,
#             "r10": 0xf8,
#             "r11": 0x100,
#             "r12": 0x108,
#             "r13": 0x110,
#             "r14": 0x118,
#             "r15": 0x120,
#             # "rflags, 0x128,
#             # "cw": 0x130,
#             # "mxcsr": 0x134,
#         }
#         for reg, loc in custom_vars_dict.items():
#             assert(claripy.is_true(self.entry_state.registers.load(reg) == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + loc].uint64_t.resolved))
#
#
#         #assert(claripy.is_true(self.entry_state.regs.sseround == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x134].uint32_t.resolved))
#         #assert(claripy.is_true(self.entry_state.registers.load("cw") == self.simgr.found[0].mem[self.simgr.found[0].registers.load("gs") + 0x130].uint32_t.resolved))
#
#         # TODO: check the flags register
#         if self.simgr.found[0].solver.satisfiable(extra_constraints=[self.simgr.found[0].regs.dflag != 0x1]):
#             print("error!")
#             log.debug("######### ENTERING ZEROED_REG ERROR %s %s ###############", "dflag", self.simgr.found[0].regs.dflag)
#         # TODO: fix this!
#         # if self.simgr.found[0].solver.satisfiable(extra_constraints=[self.simgr.found[0].regs.acflag != 0x1]):
#         #     print("error! : ", "ac flag!")
#         #     log.debug("######### ENTERING ZEROED_REG ERROR %s %s ###############", "acflag", self.simgr.found[0].regs.acflag)
#
#         # TODO: check the xsave & xrstor working!
#         # NOTE: do I just have to implement this myself? (This is not provided by angr, but won't know if my implementation is fully correct? )

class RegisterEnteringValidation(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### REGISTER ENTERING VALIDATION ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Entering:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         "EnteringSanitisation")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            assert "no_sanitisation" in kwargs
            if not kwargs["no_sanitisation"]:
                violation = Validation.entering(self.state)
                if violation is not None:
                    self.state.enclave.set_violation(violation)
                    self.state.enclave.found_violation = True
        self.state.enclave.entry_sanitisation_complete = True
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToTrusted(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### TRUSTED ###############")
        assert self.state.has_plugin("enclave")
        if not (self.state.enclave.control_state == ControlState.Entering
                or self.state.enclave.control_state == ControlState.Ocall):
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         ControlState.Trusted)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        elif not self.state.enclave.entry_sanitisation_complete:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         "Entering Trusted without entry sanitisation")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.NoReadOrWrite
            self.state.enclave.control_state = ControlState.Trusted
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExiting(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITING ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Trusted:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         ControlState.Exiting)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.Write
            self.state.enclave.control_state = ControlState.Exiting
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExited(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITED ###############")
        assert self.state.has_plugin("enclave")
        if not (self.state.enclave.control_state == ControlState.Exiting
                or self.state.enclave.control_state == ControlState.Entering):
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, ControlState.Exited)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            if self.state.enclave.control_state == ControlState.Exiting:
                assert "no_sanitisation" in kwargs
                if not kwargs["no_sanitisation"]:
                    violation = Validation.exited(self.state)
                    if violation is not None:
                        self.state.enclave.set_violation(violation)
                        self.state.enclave.found_violation = True
            self.state.enclave.control_state = ControlState.Exited
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToOcall(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### OCALL ###############")
        log.debug(hex(self.state.addr))
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Trusted:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, ControlState.Ocall)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.ReadWrite
            self.state.enclave.control_state = ControlState.Ocall
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class OcallAbstraction(angr.SimProcedure):
    def run(self, **kwargs):
        log.debug("######### OCALL ABSTRACTION ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Ocall:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, "OcallAbstraction")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        return self.state.solver.Unconstrained("ocall_ret",
                                               self.state.arch.bits)


class malloc(angr.SimProcedure):
    def run(self, sim_size):
        if self.state.solver.symbolic(sim_size):
            log.warning("Allocating size {}\n".format(sim_size))
            size = self.state.solver.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                log.warning(
                    "Allocation request of %d bytes exceeded maximum of %d bytes; allocating %d bytes",
                    size, self.state.libc.max_variable_size,
                    self.state.libc.max_variable_size)
                size = self.state.libc.max_variable_size
                self.state.add_constraints(sim_size == size)
        else:
            size = self.state.solver.eval(sim_size)
        return self.state.heap._malloc(sim_size)


class Validation:
    def entering(state):
        log.debug("######### VALIDATION REGS ###############")
        state.solver.simplify()
        zeroed_regs = [
            "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ]
        error_regs = []
        for reg_name in zeroed_regs:
            if state.solver.satisfiable(
                    extra_constraints=[state.registers.load(reg_name) != 0x0]):
                log.debug(
                    "######### ENTERING ZEROED_REG ERROR %s %s ###############",
                    reg_name, state.registers.load(reg_name))
                error_regs.append(reg_name)

        if state.solver.satisfiable(extra_constraints=[state.regs.ac != 0x0]):
            log.debug("######### ENTERING AC ERROR %s ###############",
                      state.regs.ac)
            error_regs.append("ac")
        # DF SET is 0xffffffffffffffff in angr
        # whereas DF CLEAR = 0x1
        if state.solver.satisfiable(
                extra_constraints=[state.regs.dflag != 0x1]):
            log.debug("######### ENTERING DF ERROR %s ###############",
                      state.regs.dflag)
            error_regs.append("df")

        if error_regs:
            return (ViolationType.EntrySanitisation,
                    ViolationType.EntrySanitisation.to_msg(), error_regs)

    def exited(state):
        state.solver.simplify()
        zeroed_regs = [
            "rdx", "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ]
        error_regs = []
        for reg_name in zeroed_regs:
            if state.solver.satisfiable(
                    extra_constraints=[state.registers.load(reg_name) != 0x0]):
                log.debug(
                    "######### EXITING ZEROED_REG ERROR %s %s ###############",
                    reg_name, state.registers.load(reg_name))
                error_regs.append(reg_name)

        if state.solver.satisfiable(extra_constraints=[state.regs.ac != 0x0]):
            log.debug("######### ENTERING AC ERROR %s ###############",
                      state.regs.ac)
            error_regs.append("ac")
        # DF SET is 0xffffffffffffffff in angr
        # whereas DF CLEAR = 0x1
        if state.solver.satisfiable(
                extra_constraints=[state.regs.dflag != 0x1]):
            log.debug("######### ENTERING DF ERROR %s ###############",
                      state.regs.dflag)
            error_regs.append("df")

        if error_regs:
            return (ViolationType.ExitSanitisation,
                    ViolationType.ExitSanitisation.to_msg(), error_regs)

