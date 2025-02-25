from __future__ import annotations
import weakref
from functools import cached_property
from typing import TYPE_CHECKING

from binexport.operand import OperandBinExport

if TYPE_CHECKING:
    from .program import ProgramBinExport
    from .function import FunctionBinExport
    from .binexport2_pb2 import BinExport2
    from binexport.types import Addr


class InstructionBinExport:
    """
    Instruction class. It represents an instruction with its operands.
    """

    def __init__(
        self,
        program: weakref.ref[ProgramBinExport],
        function: weakref.ref[FunctionBinExport],
        addr: Addr,
        i_idx: int,
    ):
        """
        :param program: Weak reference to the program
        :param function: Weak reference to the function
        :param addr: address of the instruction (computed outside)
        :param i_idx: instruction index in the protobuf data structure
        """
        self.addr: Addr = addr  #: instruction address
        self._program = program
        self._function = function
        self._idx = i_idx
        self.data_refs: set[Addr] = self.program.data_refs[self._idx]  #: Data references address
        self.bytes = self.pb_instr.raw_bytes  #: bytes of the instruction (opcodes)
        self.disasm = f"{self.mnemonic} {', '.join(str(o) for o in self.operands)}"

    def __hash__(self) -> int:
        return hash(self.addr)

    def __str__(self) -> str:
        return "%s %s" % (self.mnemonic, ", ".join(str(o) for o in self.operands))

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.addr:#08x}: {self.mnemonic} {', '.join(str(x) for x in self.operands)}>"

    @property
    def program(self) -> ProgramBinExport:
        """
        Program associated with this instruction.
        """
        return self._program()

    @property
    def pb_instr(self) -> BinExport2.Instruction:
        """
        Protobuf instruction object.
        """
        return self.program.proto.instruction[self._idx]

    @property
    def mnemonic(self) -> str:
        """
        Mnemonic string as gathered by binexport (with prefix).
        """
        return self.program.proto.mnemonic[self.pb_instr.mnemonic_index].name

    @cached_property
    def operands(self) -> list[OperandBinExport]:
        """
        Returns a list of the operands instanciated dynamically on-demand.
        The list is cached by default, to erase the cache delete the attribute.

        :return: list of operands
        """

        return [
            OperandBinExport(self._program, self._function, weakref.ref(self), op_idx)
            for op_idx in self.pb_instr.operand_index
        ]
