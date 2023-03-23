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

from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

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
            rip = self.state.solver.eval(self.state.regs.rip)
            log.critical("Unexpected EEXIT (rip = " + hex(rip) + ")")
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

class Xrstor(angr.SimProcedure):
    IS_FUNCTION = False

    def read(self, ptr, length, cast_to):
        return self.state.solver.eval(
                    self.state.memory.load(ptr, length, disable_actions=True, inspect=False),
                    cast_to=cast_to
                )

    def run(self, **kwargs):
        insn = kwargs["insn"]
        # Decode instruction
        # ref https://github.com/capstone-engine/capstone/blob/ab8892658790eb44f03b9047c6765bc3812d1ae1/bindings/python/test_x86.py#L119
        if len(insn.operands) != 1:
            self.logger.error("Unexpected xrstor instruction encoding: " + str(insn))
            exit(1)

        if insn.operands[0].type == X86_OP_MEM:
            base_reg = insn.operands[0].mem.base
            index = insn.operands[0].mem.index
            disp = insn.operands[0].mem.disp
            scale = insn.operands[0].mem.scale

            if insn.operands[0].mem.segment != 0:
                self.logger.error("Unexpected xrstor instruction encoding (unrecognized segment): " + str(insn))
                exit(1)

            if insn.reg_name(base_reg) != "rip":
                self.logger.error("Unexpected xrstor instruction encoding (unrecognized base reg): " + str(insn))
                exit(1)

            rip = self.state.solver.eval(self.state.regs.rip)
            xsave_area = rip + index * scale + disp + insn.size
        else:
            self.logger.error("Unexpected xrstor instruction encoding")
            exit(1)

        # The enclave sets XCR0, we don't know it at the elf level
        xcr0 = 0xFFFFFFFFFFFFFFFF
        edx = self.state.solver.eval(self.state.regs.rdx) & 0xFFFFFFFF
        eax = self.state.solver.eval(self.state.regs.rax) & 0xFFFFFFFF
        rfbm = edx << 32 | eax & xcr0

        # Vol 1, chpt 13.4 XSAVE Area
        # https://cdrdv2.intel.com/v1/dl/getContent/671200
        xsave_header = self.read(xsave_area + 512, 64, cast_to=bytes)
        xstate_bv = self.read(xsave_area + 512, 8, cast_to=int)
        xcomp_bv = self.read(xsave_area + 512 + 8, 8, cast_to=int)
        compmask = xcomp_bv
        rstormask = xstate_bv

        if compmask & (0x1 << 63) == (0x1 << 63):
            self.logger.error("Unexpected xrstor instruction evaluation (compact format not supported)")
            exit(1)
        else:
            to_be_restored = rfbm & rstormask
            to_be_initialized = rfbm & ~rstormask
            # If RFBM[i] = 0, XRSTOR does not update state component i. There is an exception
            # if RFBM[1] = 0 and RFBM[2] = 1. In this case, the standard form of XRSTOR will
            # load MXCSR from memory, even though MXCSR is part of state component 1 — SSE.
            # The compacted form of XRSTOR does not make this exception.
            # We may be in this case as xcr0 is set by the enclave at a later stage
            EXPECTED_COMPONENT0 = [0x00] * 32
            EXPECTED_COMPONENT0[24] = 0x80
            EXPECTED_COMPONENT0[25] = 0x1f

            component0 = self.read(xsave_area, 32, cast_to=bytes)
            if list(component0) != EXPECTED_COMPONENT0:
                print("Unexpected mxcsr initialization")
                exit(1)

            for i in range(0, 64):
                mask = 0x1 << i
                if to_be_restored & mask == mask:
                    self.logger.error("Unexpected xrstor instruction evaluation (component " + str(i) + "restored)")
                    self.logger.error("  %rip = " + hex(rip))
                    self.logger.error("  %eax = " + hex(eax))
                    self.logger.error("  %edx = " + hex(edx))
                    self.logger.error("  to_be_restored = " + hex(to_be_restored))
                    exit(1)
                elif to_be_initialized & mask == mask:
                    # If RFBM[i] = 1 and bit i is clear in the XSTATE_BV field in the XSAVE header,
                    # XRSTOR initializes state component i
                    # (XRSTOR x86 instruction manual)
                    #print("Initialize xsave component " + str(i))
                    ()
                else:
                    self.logger.error("Unexpected xrstor instruction evaluation (component " + str(i) + "not initialized)")
                    exit(1)

        self.state.globals["xsave_initialization"] = True
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
        log.debug("movsq detected! Simulating single move")
        rdi = self.state.registers.load("rdi")
        rsi = self.state.registers.load("rsi")
        # TODO check that req instruction prefix executes correctly
        self.state.memory.store(rdi, rsi)
        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')

class Movsb(angr.SimProcedure):
    IS_FUNCTION = False
    def run(self, **kwargs):
        print("movsb detected! Simulating single move")
        pass
        #rdi = self.state.registers.load("rdi")
        #rsi = self.state.registers.load("rsi")
        # TODO check that req instruction prefix executes correctly
        #self.state.memory.store(rdi, rsi)
        #self.successors.add_successor(
        #    self.state, self.state.addr + kwargs["bytes_to_skip"],
        #    self.state.solver.true, 'Ijk_Boring')
