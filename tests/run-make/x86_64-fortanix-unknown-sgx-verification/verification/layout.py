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


class Layout:
    # As per SDK definitions:

    SE_PAGE_SIZE = 0x1000
    SE_PAGE_SHIFT = 12
    SE_GUARD_PAGE_SIZE = 0x10000
    TCS_SIZE = SE_PAGE_SIZE
    SSA_FRAME_SIZE = 1
    SSA_NUM = 2
    TD_SIZE = 15 * 8

    def page_count_for_size(self, size):
        return size >> self.SE_PAGE_SHIFT

    def size_from_page_count(self, count):
        return count << self.SE_PAGE_SHIFT

    def round_size_for_page(self, size):
        return self.size_from_page_count(self.page_count_for_size(size))

    def round_to_page(self, size):
        return (((size) + ((self.SE_PAGE_SIZE) - 1))
                & ~((self.SE_PAGE_SIZE) - 1))

    #def __init__(self, project):
        #project.loader.memory.add_backer(
        #    self.heap_start,
        #    bytearray(self.td_start + self.round_size_for_page(self.td_size) -
        #              self.heap_start))

    def print(self):
        print("Heap start: ", hex(self.heap_start))
        print("Heap size: ", hex(self.heap_size))
        print("Stack start: ", hex(self.stack_start))
        print("Stack size: ", hex(self.stack_size))
        print("TCS start: ", hex(self.tcs_start))
        print("TCS size: ", hex(self.tcs_size))
        print("SSA start: ", hex(self.ssa_start))
        print("SSA size: ", hex(self.ssa_size))
        print("TD start: ", hex(self.td_start))
