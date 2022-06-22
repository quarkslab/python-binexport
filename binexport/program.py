import pathlib
import logging
import networkx
import weakref
from collections import defaultdict

from binexport.binexport2_pb2 import BinExport2
from binexport.function import FunctionBinExport
from binexport.types import FunctionType


class ProgramBinExport(dict):
    """
    Program class that represent the binexport with high-level functions
    and an easy to use API. It inherits from a dict which is used to
    reference all functions based on their address.
    """

    def __init__(self, file: pathlib.Path | str):
        """
        Program constructor. It takes the file path, parse the binexport and
        initialize all the functions and instructions.
        :param file: .BinExport file path
        """
        super(ProgramBinExport, self).__init__()

        self._pb = BinExport2()
        with open(file, "rb") as f:
            self._pb.ParseFromString(f.read())
        self.mask = (
            0xFFFFFFFF if self.architecture.endswith("32") else 0xFFFFFFFFFFFFFFFF
        )
        self.fun_names = {}
        self.callgraph = networkx.DiGraph()

        # Make the data refs map {instruction index -> address referred}
        self.data_refs = defaultdict(set)
        for entry in self.proto.data_reference:
            self.data_refs[entry.instruction_index].add(entry.address)

        # Make the address comment (deprecated)
        self.addr_refs = {}
        for entry in self.proto.address_comment[::-1]:
            if entry.instruction_index in self.addr_refs:
                self.addr_refs[entry.instruction_index].append(
                    self.proto.string_table[entry.string_table_index]
                )
            else:
                self.addr_refs[entry.instruction_index] = [
                    self.proto.string_table[entry.string_table_index]
                ]

        # Make the string reference
        self.string_refs = {}
        for entry in self.proto.string_reference:
            self.string_refs[entry.instruction_index] = entry.string_table_index

        count_f = 0
        coll = 0
        # Load all the functions
        for i, pb_fun in enumerate(self.proto.flow_graph):
            f = FunctionBinExport(weakref.ref(self), pb_fun=pb_fun)
            if f.addr in self:
                logging.error(f"Address collision for 0x{f.addr:x}")
                coll += 1
            self[f.addr] = f
            count_f += 1

        count_imp = 0
        # Load the callgraph
        cg = self.proto.call_graph
        for node in cg.vertex:
            if node.address not in self and node.type == cg.Vertex.IMPORTED:
                self[node.address] = FunctionBinExport(
                    weakref.ref(self), is_import=True, addr=node.address
                )
                count_imp += 1
            if node.address not in self:
                logging.error(
                    f"Missing function address: 0x{node.address:x} ({node.type})"
                )
                continue

            self[node.address].type = FunctionType.from_proto(node.type)
            if node.demangled_name:
                self[node.address].name = node.demangled_name
            elif node.mangled_name:
                self[node.address].name = node.mangled_name

        for edge in cg.edge:
            src = cg.vertex[edge.source_vertex_index].address
            dst = cg.vertex[edge.target_vertex_index].address
            self.callgraph.add_edge(src, dst)
            self[src].children.add(self[dst])
            self[dst].parents.add(self[src])

        # Create a map of function names for quick lookup later on
        for f in self.values():
            self.fun_names[f.name] = f

        logging.debug(
            f"total all:{count_f}, imported:{count_imp} collision:{coll} (total:{count_f + count_imp + coll})"
        )

    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self.name}>"

    @staticmethod
    def from_binary_file(
        exec_file: pathlib.Path | str,
        output_file: str | pathlib.Path = "",
        open_export: bool = True,
    ) -> "ProgramBinExport | None":
        """
        Generate the .BinExport file for the given program and return an instance
        of ProgramBinExport.
        .. warning:: That function requires the module ``idascript``
        :param exec_file: executable file path
        :param output_file: BinExport output file
        :param open_export: whether or not to open the binexport after export
        :return: an instance of ProgramBinExport
        """
        from idascript import IDA

        if not output_file:
            output_file = binexport_file = pathlib.Path(exec_file).with_suffix(
                ".BinExport"
            )

        ida = IDA(
            exec_file,
            script_file=None,
            script_params=[
                "BinExportAutoAction:BinExportBinary",
                f"BinExportModule:{output_file}",
            ],
        )
        ida.start()
        retcode = ida.wait()

        logging.info(
            "%s successfully exported to BinExport [code: %d]" % (exec_file, retcode)
        )

        if output_file:
            output_file = pathlib.Path(output_file)
            binexport_file.rename(output_file)
            binexport_file = output_file

        if binexport_file.is_file():
            return ProgramBinExport(binexport_file) if open_export else None
        else:
            logging.error(
                "export with IDA failed for some reasons (binexport not found)"
            )
            return None

    @property
    def proto(self) -> BinExport2:
        """
        :return: Low-level BinExport2 protobuf object
        """
        return self._pb

    @property
    def name(self) -> str:
        """
        Return the name of the program (as exported by binexport)
        :return: name of the program
        """
        return self.proto.meta_information.executable_name

    @property
    def architecture(self) -> str:
        """
        Returns the architecture suffixed with address size ex: x86_64, x86_32
        :return: architecture name
        """
        return self.proto.meta_information.architecture_name
