from __future__ import annotations
import weakref
from functools import cached_property
from typing import TYPE_CHECKING

from binexport.utils import instruction_index_range, get_instruction_address
from binexport.instruction import InstructionBinExport

if TYPE_CHECKING:
    from binexport.program import ProgramBinExport
    from binexport.function import FunctionBinExport
    from binexport.binexport2_pb2 import BinExport2
    from binexport.types import Addr


class BasicBlockBinExport:
    """
    Basic block class.
    """

    def __init__(
        self,
        program: weakref.ref[ProgramBinExport],
        function: weakref.ref[FunctionBinExport],
        pb_bb: BinExport2.BasicBlock,
    ):
        """
        :param program: Weak reference to the program
        :param function: Weak reference to the function
        :param pb_bb: protobuf definition of the basic block
        """

        super(BasicBlockBinExport, self).__init__()

        self._program = program
        self._function = function
        self.pb_bb = pb_bb

        self.addr: Addr = None  #: basic bloc address
        self.bytes = b""  #: bytes of the basic block
        self._len = 0  #: Length of the basic block (number of instructions)

        # Ranges are in fact the true basic blocks but BinExport
        # doesn't have the same basic block semantic and merge multiple basic blocks into one.
        # For example: BB_1 -- unconditional_jmp --> BB_2
        # might be merged into a single basic block so the edge gets lost.
        for rng in pb_bb.instruction_index:
            for idx in instruction_index_range(rng):
                self.bytes += self.program.proto.instruction[idx].raw_bytes
                self._len += 1

                # The first instruction determines the basic block address
                if self.addr is None:
                    self.addr = get_instruction_address(self.program.proto, idx)

    def __hash__(self) -> int:
        """
        Make function hashable to be able to store them in sets (for parents, children)

        :return: address of the basic block
        """
        return hash(self.addr)

    def __str__(self) -> str:
        return "\n".join(str(i) for i in self.instructions.values())

    def __repr__(self) -> str:
        return "<%s:0x%x>" % (type(self).__name__, self.addr)

    def __len__(self) -> int:
        return self._len

    @property
    def program(self) -> ProgramBinExport:
        """
        Wrapper on weak reference on ProgramBinExport

        :return: object :py:class:`ProgramBinExport`, program associated to the basic block
        """
        return self._program()

    @property
    def function(self) -> FunctionBinExport:
        """
        Wrapper on weak reference on FunctionBinExport

        :return: object :py:class:`FunctionBinExport`, function associated to the basic block
        """
        return self._function()

    @cached_property
    def contiguous_ranges(self) -> list[tuple[Addr, bytes]]:
        """
        The contiguous ranges of instructions contained in this basic block. That identifies
        the *real* basic blocks, as BinExport's basic blocks do not necessarily represent a
        contiguous block of instructions.

        :return: List of tuples (begin address, bytes), each of them representing a contiguous
                 block of instructions.
        """

        ranges = []

        # Ranges are in fact the true basic blocks but BinExport
        # doesn't have the same basic block semantic and merge multiple basic blocks into one.
        # For example: BB_1 -- unconditional_jmp --> BB_2
        # might be merged into a single basic block so the edge gets lost.
        for rng in self.pb_bb.instruction_index:
            rng_bytes = b""
            rng_addr = None
            for idx in instruction_index_range(rng):
                rng_bytes += self.program.proto.instruction[idx].raw_bytes

                # The first instruction determines the basic block address
                if rng_addr is None:
                    rng_addr = get_instruction_address(self.program.proto, idx)
            ranges.append((rng_addr, rng_bytes))

        return ranges

    @cached_property
    def instructions(self) -> dict[Addr, InstructionBinExport]:
        """
        Returns a dict which is used to reference all the instructions in this basic
        block by their address.
        The object returned is by default cached, to erase the cache delete the attribute.

        :return: dictionary of addresses to instructions
        """

        instructions = {}

        # Ranges are in fact the true basic blocks but BinExport
        # doesn't have the same basic block semantic and merge multiple basic blocks into one.
        # For example: BB_1 -- unconditional_jmp --> BB_2
        # might be merged into a single basic block so the edge gets lost.
        for rng in self.pb_bb.instruction_index:
            for idx in instruction_index_range(rng):
                inst_addr = get_instruction_address(self.program.proto, idx)

                instructions[inst_addr] = InstructionBinExport(
                    self._program, self._function, inst_addr, idx
                )

        return instructions
