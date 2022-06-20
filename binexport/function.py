import logging
import weakref
import networkx

from binexport.utils import get_basic_block_addr
from binexport.basic_block import BasicBlockBinExport
from binexport.types import FunctionType


class FunctionBinExport(dict):
    """
    Class that represent functions. It inherits from a dict which is used to
    reference all basic blocks by their address. Also references its parents
    and children (function it calls).
    """

    def __init__(
        self,
        program: weakref.ref["ProgramBinExport"],
        *,
        pb_fun: "BinExport2.FlowGraph | None" = None,
        is_import: bool = False,
        addr: int | None = None,
    ):
        """
        Constructor. Iterates the FlowGraph structure and initialize all the
        basic blocks and instruction accordingly.
        :param program: weak reference to program (used to navigate pb fields contained inside)
        :param pb_fun: FlowGraph protobuf structure
        :param is_import: whether or not its an import function (if so does not initialize bb etc..)
        :param addr: address of the function (info avalaible in the call graph)
        """
        super(FunctionBinExport, self).__init__()

        self.addr = addr  # Optional address
        self.parents = set()
        self.children = set()
        self.graph = networkx.DiGraph()
        self._type = None  # Set by the Program constructor
        self._name = None  # Set by the Program constructor
        self._program = program

        if is_import:
            if self.addr is None:
                logging.error("Missing function address for imported function")
            return

        assert pb_fun is not None, "pb_fun must be provided"

        self.addr = get_basic_block_addr(
            self.program.proto, pb_fun.entry_basic_block_index
        )

        # Load the basic blocks
        bb_i2a = {}  # Map {basic block index -> basic block address}
        bb_count = 0
        for bb_idx in pb_fun.basic_block_index:
            bb_count += 1
            basic_block = BasicBlockBinExport(
                self._program,
                weakref.ref(self),
                self.program.proto.basic_block[bb_idx],
            )

            if basic_block.addr in self:
                logging.error(
                    "0x%x basic block address (0x%x) already in(idx:%d)"
                    % (self.addr, basic_block.addr, bb_idx)
                )

            self[basic_block.addr] = basic_block
            bb_i2a[bb_idx] = basic_block.addr
            self.graph.add_node(basic_block.addr)

        if bb_count != len(self):
            logging.error(
                "Wrong basic block number %x, bb:%d, self:%d"
                % (self.addr, len(pb_fun.basic_block_index), len(self))
            )

        # Load the edges between blocks
        for edge in pb_fun.edge:
            # Source will always be in a basic block
            bb_src = bb_i2a[edge.source_basic_block_index]

            # Target might be a different function and not a basic block.
            # e.g. in case of a jmp to another function (or a `bl` in ARM)
            if edge.target_basic_block_index not in bb_i2a:
                continue

            bb_dst = bb_i2a[edge.target_basic_block_index]
            self.graph.add_edge(bb_src, bb_dst)

    def __hash__(self) -> int:
        """
        Make function hashable to be able to store them in sets (for parents, children)
        :return: address of the function
        """
        return hash(self.addr)

    def __repr__(self) -> str:
        return "<%s: 0x%x>" % (type(self).__name__, self.addr)

    @property
    def program(self) -> "ProgramBinExport":
        """Wrapper on weak reference on ProgramBinExport"""
        return self._program()

    @property
    def name(self) -> str:
        """
        Name of the function if it exists otherwise like IDA with sub_XXX
        :return: name of the function
        """
        return self._name if self._name else "sub_%X" % self.addr

    @name.setter
    def name(self, name: str) -> None:
        """
        Function name setter (available in the call graph of the pb object)
        :param name: name to give the function
        :return: None
        """
        self._name = name

    @property
    def type(self) -> FunctionType:
        """
        Type of the function as a FunctionType
        :return: type enum of the function
        """
        return self._type

    @type.setter
    def type(self, value: FunctionType) -> None:
        """
        Set the type of the function
        :param value: type enum to give the function
        :return: None
        """
        self._type = value

    def is_import(self) -> bool:
        """
        Returns whether or not the function is an import
        :return: boolean indicating if the function is an import
        """
        return self.type == FunctionType.IMPORTED
