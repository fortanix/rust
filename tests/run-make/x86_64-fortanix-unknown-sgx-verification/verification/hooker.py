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
import angr
import sys
import pyvex
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from simulation_procedures import SimEnclu, Nop, Rdrand, UD2, Movsq

class Hooker:
    def setup(self, proj):
        self.instruction_hooker(proj, self.instruction_replacement())
        return proj

    def instruction_hooker(self, angr_proj, ins_to_sim_proc):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = False #True  # If invalid instruction is found, search for next valid one instead of aborting
        for section in angr_proj.loader.main_object.sections:
            if section.is_executable:
                section_bytes = angr_proj.loader.memory.load(
                    section.vaddr, section.memsize)
                for i in md.disasm(section_bytes, section.vaddr):
                    sim_proc = ins_to_sim_proc(i)
                    if sim_proc is not None:
                        logging.debug("0x%x:\t%s\t%s\t%s" %
                                      (i.address, i.mnemonic, i.op_str,
                                       i.size))
                        angr_proj.hook(i.address, hook=sim_proc, length=i.size)

    def instruction_replacement(self):
        def replace(capstone_instruction) -> angr.SimProcedure:
            if capstone_instruction.mnemonic == "enclu":
                return SimEnclu()
            elif "xsave" in capstone_instruction.mnemonic:
                return Nop(bytes_to_skip=capstone_instruction.size)  # NOTE: the original "guardian code" contained a mistake here!
            elif "xrstor" in capstone_instruction.mnemonic:
                return Nop(bytes_to_skip=capstone_instruction.size)
            elif capstone_instruction.mnemonic == "fxrstor64":
                return Nop(bytes_to_skip=capstone_instruction.size)
            elif capstone_instruction.mnemonic == "rdrand":
                return Rdrand()
            elif capstone_instruction.mnemonic == "ud2":
                return UD2()
            elif "verw" in capstone_instruction.mnemonic:
                return Nop(bytes_to_skip=capstone_instruction.size)
            elif "movsq" in capstone_instruction.mnemonic:
                return Movsq(bytes_to_skip=capstone_instruction.size)
            else:
                None

        return replace
