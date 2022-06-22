import weakref

from binexport.operand import OperandBinExport


class InstructionBinExport:
    """
    Instruction class. It represent an instruction with its operands.
    """

    def __init__(
        self,
        program: weakref.ref["ProgramBinExport"],
        function: weakref.ref["FunctionBinExport"],
        addr: int,
        i_idx: int,
    ):
        """
        Instruction constructor.
        :param program: Weak reference to the program
        :param function: Weak reference to the function
        :param addr: address of the instruction (computed outside)
        :param i_idx: instuction index in the protobuf data structure
        """
        self.addr = addr
        self._program = program
        self._function = function
        self._idx = i_idx
        self.data_refs = self.program.data_refs[self._idx]
        self.bytes = self.pb_instr.raw_bytes

    def __hash__(self) -> int:
        return hash(self.addr)

    def __str__(self) -> str:
        return "%s %s" % (self.mnemonic, ", ".join(str(o) for o in self.operands))

    def __repr__(self) -> str:
        return "<%s 0x%x: %s %s>" % (
            type(self).__name__,
            self.addr,
            self.mnemonic,
            ", ".join(str(x) for x in self.operands),
        )

    @property
    def program(self) -> "ProgramBinExport":
        """Wrapper on weak reference on ProgramBinExport"""
        return self._program()

    @property
    def pb_instr(self) -> "BinExport2.Instruction":
        """
        Returns the Instruction object in the binexport protobuf
        :return: Instruction binexport object
        """
        return self.program.proto.instruction[self._idx]

    @property
    def mnemonic(self) -> str:
        """
        Returns the mnemonic string as gathered by binexport
        :return: mnemonic string (with prefix)
        """
        return self.program.proto.mnemonic[self.pb_instr.mnemonic_index].name

    @property
    def operands(self) -> list[OperandBinExport]:
        """
        Returns a list of the operands instanciated dynamically on-demand.
        :return: list of operand objects
        """
        return [
            OperandBinExport(self._program, self._function, weakref.ref(self), op_idx)
            for op_idx in self.pb_instr.operand_index
        ]
