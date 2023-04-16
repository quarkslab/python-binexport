from __future__ import annotations, absolute_import
import enum
from typing import TypeAlias
import enum_tools.documentation

from binexport.binexport2_pb2 import BinExport2


Addr: TypeAlias = int
"""An integer representing an address within a program"""

@enum_tools.documentation.document_enum
class FunctionType(enum.Enum):
    """
    Function types as defined by IDA
    """

    NORMAL = enum.auto()    # doc: Normal function
    LIBRARY = enum.auto()   # doc: library function
    IMPORTED = enum.auto()  # doc: imported function (don't have content)
    THUNK = enum.auto()     # doc: thunk function (trampoline to another function)
    INVALID = enum.auto()   # doc: invalid function (as computed by IDA)

    @staticmethod
    def from_proto(function_type: BinExport2.CallGraph.Vertex.Type) -> FunctionType:
        mapping = {
            BinExport2.CallGraph.Vertex.Type.NORMAL: FunctionType.NORMAL,
            BinExport2.CallGraph.Vertex.Type.LIBRARY: FunctionType.LIBRARY,
            BinExport2.CallGraph.Vertex.Type.IMPORTED: FunctionType.IMPORTED,
            BinExport2.CallGraph.Vertex.Type.THUNK: FunctionType.THUNK,
            BinExport2.CallGraph.Vertex.Type.INVALID: FunctionType.INVALID,
        }

        return mapping.get(function_type, FunctionType.INVALID)

@enum_tools.documentation.document_enum
class ExpressionType(enum.Enum):
    """
    Expression type derived from protobuf expression types.
    """

    FUNC_NAME = enum.auto()        # doc: function name
    VAR_NAME = enum.auto()         # doc: variable name
    IMMEDIATE_INT = enum.auto()    # doc: immediate value
    IMMEDIATE_FLOAT = enum.auto()  # doc: float expression
    SYMBOL = enum.auto()           # doc: symbol expression
    REGISTER = enum.auto()         # doc: register expression
    SIZE = enum.auto()             # doc: size expression (byte, dword ..)
