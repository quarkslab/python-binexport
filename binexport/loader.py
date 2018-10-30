from __future__ import absolute_import
import logging
from collections import defaultdict
import networkx
from typing import Dict, List, Optional, Generator, Tuple, Union
from binexport.binexport2_pb2 import BinExport2


def _get_instruction_address(pb: BinExport2, inst_idx: int) -> int:
    inst = pb.instruction[inst_idx]
    if inst.HasField('address'):
        return inst.address
    else:
        return _backtrack_instruction_address(pb, inst_idx)


def _backtrack_instruction_address(pb: BinExport2, idx) -> int:
    tmp_sz = 0
    tmp_idx = idx
    if tmp_idx == 0:
        return pb.instruction[tmp_idx].address
    while True:
        tmp_idx -= 1
        tmp_sz += len(pb.instruction[tmp_idx].raw_bytes)
        if pb.instruction[tmp_idx].HasField('address'):
            break
    return pb.instruction[tmp_idx].address + tmp_sz


def _get_basic_block_addr(pb: BinExport2, bb_idx: int) -> int:
    inst = pb.basic_block[bb_idx].instruction_index[0].begin_index
    return _get_instruction_address(pb, inst)


class ProgramBinExport(dict):
    def __init__(self, file: str):
        super(dict, self).__init__()
        self._pb = BinExport2()
        with open(file, 'rb') as f:
            self._pb.ParseFromString(f.read())
        self._mask = 0xFFFFFFFF if self.architecture.endswith("32") else 0xFFFFFFFFFFFFFFFF
        self.fun_names = {}

        # Make the data refs map
        data_refs = {}
        for entry in self.proto.data_reference[::-1]:
            if entry.instruction_index in data_refs:
                data_refs[entry.instruction_index].append(entry.address)
            else:
                data_refs[entry.instruction_index] = [entry.address]

        # Make the address comment
        addr_refs = {}
        for entry in self.proto.address_comment[::-1]:
            if entry.instruction_index in addr_refs:
                addr_refs[entry.instruction_index].append(self.proto.string_table[entry.string_table_index])
            else:
                addr_refs[entry.instruction_index] = [self.proto.string_table[entry.string_table_index]]

        count_f = 0
        coll = 0
        # Load all the functions
        for i, pb_fun in enumerate(self.proto.flow_graph):
            f = FunctionBinExport(self, data_refs, addr_refs, pb_fun)
            if f.addr in self:
                logging.error("Address collision for 0x%x" % f.addr)
                coll += 1
            self[f.addr] = f
            count_f += 1

        count_imp = 0
        # Load the callgraph
        cg = self.proto.call_graph
        for node in cg.vertex:
            if node.address not in self and node.type == cg.Vertex.IMPORTED:
                self[node.address] = FunctionBinExport(self, data_refs, addr_refs, None,
                                                       is_import=True, addr=node.address)
                count_imp += 1
            if node.address not in self and node.type == cg.Vertex.NORMAL:
                logging.error("Missing function address: 0x%x (%d)" % (node.address, node.type))

            self[node.address].type = node.type
            self[node.address].name = node.mangled_name
        for edge in cg.edge:
            src = cg.vertex[edge.source_vertex_index].address
            dst = cg.vertex[edge.target_vertex_index].address
            self[src].children.add(self[dst])
            self[dst].parents.add(self[src])

        for f in self.values():  # Create a map of function names for quick lookup later on
            self.fun_names[f.name] = f

        logging.debug("total all:%d, imported:%d collision:%d (total:%d)" %
                      (count_f, count_imp, coll, (count_f + count_imp + coll)))

    def addr_mask(self, value: int) -> int:
        return value & self._mask

    @property
    def proto(self) -> BinExport2:
        return self._pb

    @property
    def name(self) -> str:
        return self.proto.meta_information.executable_name

    @property
    def architecture(self) -> str:
        return self.proto.meta_information.architecture_name

    def __repr__(self) -> str:
        return '<BinExportProgram:%s>' % self.name


class FunctionBinExport(dict):
    def __init__(self, program: ProgramBinExport, data_refs: Dict[int, List[int]], addr_refs: Dict[int, str],
                 pb_fun: Optional[BinExport2.FlowGraph], is_import: bool = False, addr: Optional[int] = None):
        super(dict, self).__init__()
        self.addr = addr
        self.parents = set()
        self.children = set()
        self.graph = networkx.DiGraph()
        self._pb_type = None  # Set by the Program constructor
        self._name = None  # Set by the Program constructor (mangled name)

        if is_import:
            return

        self.addr = _get_basic_block_addr(program.proto, pb_fun.entry_basic_block_index)

        cur_addr = None
        prev_idx = -2
        tmp_mapping = {}
        bb_count = 0
        for bb_idx in pb_fun.basic_block_index:
            for rng in program.proto.basic_block[bb_idx].instruction_index:  # Ranges are in fact the true basic blocks!
                bb_count += 1
                bb_addr = None
                bb_data = []
                for idx in range(rng.begin_index, (rng.end_index if rng.end_index else rng.begin_index + 1)):

                    if idx != prev_idx + 1:  # if the current idx is different from the previous range or bb
                        cur_addr = None  # reset the addr has we have no guarantee on the continuity of the address

                    pb_inst = program.proto.instruction[idx]

                    if pb_inst.HasField('address'):  # If the instruction have an address set (can be 0)
                        if cur_addr is not None and cur_addr != pb_inst.address:
                            # logging.warning("cur_addr different from inst address: %x != %x (%d) (%d->%d)" %
                            #                                    (cur_addr, pb_inst.address, bb_idx, prev_idx, idx))
                            pass  # might be legit if within the basic block there is data
                            # thus within the same range not contiguous address can co-exists
                        cur_addr = pb_inst.address  # set the address to the one of inst regardless cur_addr was set
                    else:
                        if not cur_addr:  # if cur_addr_not set backtrack to get it
                            cur_addr = _get_instruction_address(program.proto, idx)

                    # At this point we should have a cur_addr correctly set to the right instruction address
                    if not bb_addr:
                        bb_addr = cur_addr

                    # At this point do the instruction initialization
                    inst = InstructionBinExport(program, self, cur_addr, idx)
                    bb_data.append(inst)
                    if idx in data_refs:  # Add some
                        inst.data_refs = data_refs[idx]
                    if idx in addr_refs:
                        inst.addr_refs = addr_refs[idx]

                    cur_addr += len(pb_inst.raw_bytes)  # increment the cur_addr with the address size
                    prev_idx = idx

                if bb_addr in self:
                    logging.error("0x%x basic block address (0x%x) already in(idx:%d)" % (self.addr, bb_addr, bb_idx))
                self[bb_addr] = bb_data
                tmp_mapping[bb_idx] = bb_addr
                self.graph.add_node(bb_addr)

        if bb_count != len(self):
            logging.error("Wrong basic block number %x, bb:%d, self:%d" %
                          (self.addr, len(pb_fun.basic_block_index), len(self)))

        # Load the edges between blocks
        for edge in pb_fun.edge:
            bb_src = tmp_mapping[edge.source_basic_block_index]
            bb_dst = tmp_mapping[edge.target_basic_block_index]
            self.graph.add_edge(bb_src, bb_dst)

    def __hash__(self) -> int:
        return hash(self.addr)

    @property
    def name(self) -> str:
        return self._name if self._name else "sub_%X" % self.addr

    @name.setter
    def name(self, name: str) -> None:
        self._name = name

    @property
    def type(self) -> BinExport2.FlowGraph.Edge.Type:
        return self._pb_type

    @type.setter
    def type(self, value: BinExport2.FlowGraph.Edge.Type) -> None:
        self._pb_type = value

    def is_import(self) -> bool:
        return self.type == BinExport2.CallGraph.Vertex.IMPORTED

    def __repr__(self) -> str:
        return '<BinExportFunction: 0x%x>' % self.addr


class InstructionBinExport:
    def __init__(self, program: ProgramBinExport, fun: FunctionBinExport, addr: int, i_idx: int):
        self._addr = addr
        self._program = program
        self._function = fun
        self._idx = i_idx
        self.data_refs = []
        self.addr_refs = []

    @property
    def addr(self) -> int:
        return self._addr

    @property
    def mnemonic(self) -> str:
        return self._program.proto.mnemonic[self._program.proto.instruction[self._idx].mnemonic_index].name

    def _me(self) -> BinExport2.Instruction:
        return self._program.proto.instruction[self._idx]

    @property
    def operands(self):
        return [OperandBinExport(self._program, self._function, self, op_idx)
                for op_idx in self._me().operand_index]

    @property
    def comment(self) -> str:
        if len(self.data_refs) >= len(self.addr_refs):
            ith = len(self.data_refs)
        else:
            ith = 0
        if self.addr_refs[ith:]:
            last = self.addr_refs[-1]
            if self.is_function_entry():
                if last == self._program[self.addr].name:
                    try:
                        return self.addr_refs[-2]
                    except IndexError:
                        return ""
            else:
                return last
        else:
            return ""

    def is_function_entry(self) -> bool:
        return self.addr in self._program

    def __repr__(self) -> str:
        return "<BinExportInstruction: 0x%x %s %s>" % \
               (self.addr, self.mnemonic, ", ".join(str(x) for x in self.operands))


class OperandBinExport:
    __sz_lookup = {'b1': 1, 'b2': 2, 'b4': 4, 'b8': 8, 'b10': 10, 'b16': 16, 'b32': 32, 'b64': 64}
    __sz_name = {1: 'byte', 2: 'word', 4: 'dword', 8: "qword", 10: 'b10', 16: "xmmword", 32: "ymmword", 64: "zmmword"}

    def __init__(self, program: ProgramBinExport, fun: FunctionBinExport, inst: InstructionBinExport, op_idx: int):
        self._program = program
        self._function = fun
        self._instruction = inst
        self._idx = op_idx

    def _me(self) -> BinExport2.Operand:
        return self._program.proto.operand[self._idx]

    def __iter_expressions(self) -> Generator[Tuple[str, Union[str, int], int, int], None, None]:
        size = None
        for idx in self._me().expression_index:
            exp = self._program.proto.expression[idx]
            if exp.type == BinExport2.Expression.SYMBOL:  # If the expression is a symbol
                if exp.symbol in self._program.fun_names:  # If it is a function name
                    f = self._program.fun_names[exp.symbol]
                    if f.type == BinExport2.CallGraph.Vertex.NORMAL:
                        yield ('codname', exp.symbol, idx, exp.parent_index)
                    elif f.type == BinExport2.CallGraph.Vertex.LIBRARY:
                        yield ('libname', exp.symbol, idx, exp.parent_index)
                    elif f.type == BinExport2.CallGraph.Vertex.IMPORTED:
                        yield ('impname', exp.symbol, idx, exp.parent_index)
                    elif f.type == BinExport2.CallGraph.Vertex.THUNK:
                        yield ('cname', exp.symbol, idx, exp.parent_index)
                    else:
                        pass  # invalid fucntion type just ignore it
                else:
                    yield ('locname', exp.symbol, idx, exp.parent_index)  # for var_, arg_

            elif exp.type == BinExport2.Expression.IMMEDIATE_INT:  # If the expression is an immediate
                if exp.immediate in self._instruction.data_refs:
                    s = "%s_%X" % (self.__sz_name[size], exp.immediate)
                    yield ('datname', s, idx, exp.parent_index)
                else:
                    if exp.immediate in self._program:  # if it is a function
                        yield ('codname', "sub_%X" % exp.immediate, idx, exp.parent_index)
                    elif exp.immediate in self._function:  # its a basic block address
                        yield ('codname', 'loc_%X' % exp.immediate, idx, exp.parent_index)
                    else:
                        yield ('number', self._program.addr_mask(exp.immediate), idx, exp.parent_index)

            elif exp.type == BinExport2.Expression.IMMEDIATE_FLOAT:
                print("IMMEDIATE FLOAT ignored:", exp)
            elif exp.type == BinExport2.Expression.OPERATOR:
                yield ('symbol', exp.symbol, idx, exp.parent_index)
            elif exp.type == BinExport2.Expression.REGISTER:
                yield ('reg', exp.symbol, idx, exp.parent_index)
            elif exp.type == BinExport2.Expression.DEREFERENCE:
                yield ('symbol', exp.symbol, idx, exp.parent_index)
            elif exp.type == BinExport2.Expression.SIZE_PREFIX:
                size = self.__sz_lookup[exp.symbol]
            else:
                print("woot:", exp)

    @property
    def expressions(self) -> Dict[str, Union[str, int]]:
        for elt in self.__iter_expressions():
            yield {'type': elt[0], 'value': elt[1]}

    def byte_size(self) -> int:
        exp = self._program.proto.expression[self._me().expression_index[0]]
        if exp.type == BinExport2.Expression.SIZE_PREFIX:
            return self.__sz_lookup[exp.symbol]
        else:
            raise Exception("First expression not byte size..")

    @property
    def type(self) -> BinExport2.Expression.Type:
        for exp in (self._program.proto.expression[idx] for idx in self._me().expression_index):
            if exp.type in [BinExport2.Expression.SIZE_PREFIX, BinExport2.Expression.OPERATOR]:
                continue
            else:
                return exp.type

        # if we reach here something necessarily went wrong
        if len(self._me().expression_index) == 1 and self._program.architecture.startswith("ARM"):
            if self._program.proto.expression[self._me().expression_index[0]].type == BinExport2.Expression.OPERATOR:
                return BinExport2.Expression.OPERATOR  # Specific handling of some ARM flags typed as OPERATOR
            else:
                logging.error("Unknown case for operand type on ARM: %s" % str(self))
        else:
            logging.error("No type found for operand: %s" % str(self))

    def __str__(self) -> str:
        is_deref = False
        exps = list(self.__iter_expressions())
        child_count = defaultdict(int)
        final_s = ""
        for _, _, idx, p_idx in exps:
            child_count[p_idx] += 1
        while exps:
            e = exps.pop(0)
            typ, value, idx, pidx = e

            if value == "[":
                is_deref = True
            if child_count[idx] > 1:
                if child_count[idx] == 2:
                    child_count[idx] -= 1
                    exps.insert(1, e)
                    continue
                else:
                    print("More than 2 child for op:%d" % self._idx)
            if isinstance(value, int):
                final_s += hex(value)
            else:  # else its normally a string
                final_s += value

        if is_deref:
            final_s += "]"
        return final_s

    def __repr__(self) -> str:
        return "<Op:%s>" % str(self)
