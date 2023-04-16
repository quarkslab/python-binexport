import weakref
from collections import OrderedDict
from typing import Optional

from binexport.utils import instruction_index_range, get_instruction_address
from binexport.instruction import InstructionBinExport
from binexport.types import Addr


class BasicBlockBinExport(OrderedDict):
    """
    Basic block.
    It inherits OrderdDict, so one can use any dictionary
    methods to access instructions.
    """

    def __init__(self, program: "ProgramBinExport", function: "FunctionBinExport", pb_bb: "BinExport2.BasicBlock"):
        """
        :param program: Weak reference to the program
        :param function: Weak reference to the function
        :param pb_bb: protobuf definition of the basic block
        """

        super(BasicBlockBinExport, self).__init__()

        self._program = program
        self.addr: Addr = None  #: basic bloc address

        self.bytes = b""  #: bytes of the basic block

        # Ranges are in fact the true basic blocks but BinExport
        # don't have the same basic block semantic and merge multiple basic blocks into one.
        # For example: BB_1 -- unconditional_jmp --> BB_2
        # might be merged into a single basic block so lose the edge
        for rng in pb_bb.instruction_index:
            for idx in instruction_index_range(rng):
                pb_inst = self.program.proto.instruction[idx]
                inst_addr = get_instruction_address(self.program.proto, idx)

                # The first instruction determines the basic block address
                # Save the first instruction to guess the instruction set
                if self.addr is None:
                    self.addr = inst_addr

                self.bytes += pb_inst.raw_bytes
                self[inst_addr] = InstructionBinExport(self._program, function, inst_addr, idx)

    def __hash__(self) -> int:
        """
        Make function hashable to be able to store them in sets (for parents, children)

        :return: address of the basic block
        """
        return hash(self.addr)

    def __str__(self) -> str:
        return "\n".join(str(i) for i in self.values())

    def __repr__(self) -> str:
        return "<%s:0x%x>" % (type(self).__name__, self.addr)

    @property
    def program(self) -> "ProgramBinExport":
        """
        Wrapper on weak reference on ProgramBinExport

        :return: object :py:class:`ProgramBinExport`, program associated to the basic block
        """
        return self._program()
