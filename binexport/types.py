from __future__ import annotations, absolute_import
import enum

from binexport.binexport2_pb2 import BinExport2


class FunctionType(enum.Enum):
    """
    Function types as defined by IDA
    """

    NORMAL = enum.auto()
    LIBRARY = enum.auto()
    IMPORTED = enum.auto()
    THUNK = enum.auto()
    INVALID = enum.auto()

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


class ExpressionType(enum.Enum):
    """
    Expression type derived from protobuf expression types.
    """

    FUNC_NAME = enum.auto()
    VAR_NAME = enum.auto()
    IMMEDIATE_INT = enum.auto()
    IMMEDIATE_FLOAT = enum.auto()
    SYMBOL = enum.auto()
    REGISTER = enum.auto()
    SIZE = enum.auto()
