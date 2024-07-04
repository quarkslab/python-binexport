from __future__ import annotations
from functools import cached_property
from typing import TYPE_CHECKING

from binexport.binexport2_pb2 import BinExport2
from binexport.types import ExpressionType
from binexport.utils import logger

if TYPE_CHECKING:
    from .program import ProgramBinExport
    from .function import FunctionBinExport
    from .instruction import InstructionBinExport


def to_signed(n: int, mask: int) -> int:
    """
    Signed representation of `n` using `mask`

    :return: the python int version of the signed integer `n` using the specified mask
    """

    assert (mask + 1) & mask == 0, "Mask must be in the form 2^n - 1"
    n &= mask
    sign_bit = (mask + 1) >> 1
    return (n ^ sign_bit) - sign_bit


class ExpressionBinExport:
    """
    Class that represent an expression node in the expression tree for a specific
    operand. The tree is inverted (each node has an edge to its parent)
    """

    __sz_lookup = {
        "b1": 1,
        "b2": 2,
        "b4": 4,
        "b8": 8,
        "b10": 10,
        "b16": 16,
        "b32": 32,
        "b64": 64,
    }
    __sz_name = {
        1: "byte",
        2: "word",
        4: "dword",
        8: "qword",
        10: "b10",
        16: "xmmword",
        32: "ymmword",
        64: "zmmword",
    }

    def __init__(
        self,
        program: ProgramBinExport,
        function: FunctionBinExport,
        instruction: InstructionBinExport,
        exp_idx: int,
        parent: ExpressionBinExport | None = None,
    ):
        """
        :param program: reference to program
        :param function: reference to function
        :param instruction: reference to instruction
        :param exp_idx: expression index in the protobuf table
        :param parent: reference to the parent expression in the tree.
                       None if it is the root.
        """

        self._idx = exp_idx
        self.parent: ExpressionBinExport | None = parent  #: parent expression if nested
        self.is_addr: bool = False  #: whether the value is referring to an address
        self.is_data: bool = False  #: whether the value is a reference to data

        # Expression object in the protobuf structure
        self.pb_expr = program.proto.expression[self._idx]

        self._parse_protobuf(program, function, instruction)

    def __hash__(self) -> int:
        return hash(self._idx)

    @property
    def type(self) -> ExpressionType:
        """
        Returns the type as defined in `ExpressionType` of the expression, after the protobuf parsing
        """

        return self._type

    @property
    def value(self) -> str | int | float:
        """
        Returns the value of the expression, after the protobuf parsing

        :return: value of the expression
        """
        return self._value

    @cached_property
    def depth(self) -> int:
        """
        Returns the depth of the node in the tree (root is depth 0).
        """
        if self.parent is None:
            return 0
        return self.parent.depth + 1

    def _parse_protobuf(
        self,
        program: ProgramBinExport,
        function: FunctionBinExport,
        instruction: InstructionBinExport,
    ) -> None:
        """
        Low-level expression parser. It populates self._type and self._value
        """
        if self.pb_expr.type == BinExport2.Expression.SYMBOL:
            self._value = self.pb_expr.symbol

            if self.pb_expr.symbol in program.fun_names:  # It is a function name
                self._type = ExpressionType.FUNC_NAME
            else:  # It is a local symbol (ex: var_, arg_)
                self._type = ExpressionType.VAR_NAME

        elif self.pb_expr.type == BinExport2.Expression.IMMEDIATE_INT:
            self._type = ExpressionType.IMMEDIATE_INT
            self._value = to_signed(self.pb_expr.immediate, program.mask)

            if self.pb_expr.immediate in instruction.data_refs:  # Data
                self.is_addr = True
                self.is_data = True
            elif self.pb_expr.immediate in program or self.pb_expr.immediate in function:  # Address
                self.is_addr = True

        elif self.pb_expr.type == BinExport2.Expression.IMMEDIATE_FLOAT:
            self._type = ExpressionType.IMMEDIATE_FLOAT
            self._value = self.pb_expr.immediate  # Cast it to float

        elif self.pb_expr.type == BinExport2.Expression.OPERATOR:
            self._type = ExpressionType.SYMBOL
            self._value = self.pb_expr.symbol

        elif self.pb_expr.type == BinExport2.Expression.REGISTER:
            self._type = ExpressionType.REGISTER
            self._value = self.pb_expr.symbol

        elif self.pb_expr.type == BinExport2.Expression.SIZE_PREFIX:
            self._type = ExpressionType.SIZE
            self._value = self.__sz_lookup[self.pb_expr.symbol]

        elif self.pb_expr.type == BinExport2.Expression.DEREFERENCE:
            self._type = ExpressionType.SYMBOL
            self._value = self.pb_expr.symbol

        else:
            logger.error(f"Malformed protobuf message. Invalid expression type {self.pb_expr.type}")
