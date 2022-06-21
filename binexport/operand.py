import logging
import weakref
from functools import cached_property

from binexport.expression import ExpressionBinExport
from binexport.types import ExpressionType


class OperandBinExport:
    """
    Class that represent an operand. The class goal is mainly
    to iterate the operand expression.
    """

    def __init__(
        self,
        program: weakref.ref["ProgramBinExport"],
        function: weakref.ref["FunctionBinExport"],
        instruction: weakref.ref["InstructionBinExport"],
        op_idx: int,
    ):
        """
        Constructor. Takes both the program, function and instruction which are used
        to compute various attributes
        :param program: Weak reference to the program
        :param function: Weak reference to the function
        :param instruction: Weak reference to the instruction
        :param op_idx: operand index in protobuf structure
        """

        self._program = program
        self._function = function
        self._instruction = instruction
        self._idx = op_idx

    def __str__(self) -> str:
        """
        Formatted string of the operand (shown in-order)
        :return: string of the operand
        """

        class Tree:
            def __init__(self, expr: ExpressionBinExport):
                self.children = []
                self.expr = expr

            def __str__(self):
                if len(self.children) == 2:  # Binary operator
                    left = str(self.children[0])
                    right = str(self.children[1])
                    return f"{left}{self.expr.value}{right}"

                inv = {"{": "}", "[": "]", "!": ""}
                final_s = ""

                if self.expr.type != ExpressionType.SIZE:  # Ignore SIZE
                    if isinstance(self.expr.value, int):
                        final_s += hex(self.expr.value)
                    else:
                        final_s += str(self.expr.value)

                final_s += ",".join(str(child) for child in self.children)

                if self.expr.type == ExpressionType.SYMBOL and self.expr.value in inv:
                    final_s += inv[self.expr.value]

                return final_s

        tree = {}
        for expr in self.expressions:
            tree[expr] = Tree(expr)
            if expr.parent:
                tree[expr.parent].children.append(tree[expr])
            else:
                root = expr
        if tree:
            return str(tree[root])
        else:
            return ""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {str(self)}>"

    @property
    def program(self) -> "ProgramBinExport":
        """Wrapper on weak reference on ProgramBinExport"""
        return self._program()

    @property
    def function(self) -> "FunctionBinExport":
        """Wrapper on weak reference on FunctionBinExport"""
        return self._function()

    @property
    def instruction(self) -> "InstructionBinExport":
        """Wrapper on weak reference on InstructionBinExport"""
        return self._instruction()

    @property
    def pb_operand(self) -> "BinExport2.Operand":
        """
        Returns the operand object in the protobuf structure
        :return: protobuf operand
        """
        return self.program.proto.operand[self._idx]

    @cached_property
    def expressions(self) -> list[ExpressionBinExport]:
        """
        Iterates over all the operand expression in a pre-order manner
        (binary operator first)
        :return: Pre-order tree traversal as a list of expression.
        """
        expr_dict = {}  # {expression protobuf idx : ExpressionBinExport}
        for exp_idx in self.pb_operand.expression_index:
            parent = None
            if self.program.proto.expression[exp_idx].HasField("parent_index"):
                parent = expr_dict[self.program.proto.expression[exp_idx].parent_index]
            expr_dict[exp_idx] = ExpressionBinExport(
                self.program, self.function, self.instruction, exp_idx, parent
            )
        return list(expr_dict.values())