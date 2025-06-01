from __future__ import annotations
import os
import pathlib
import networkx
import weakref
from textwrap import dedent
from collections import defaultdict
from tempfile import TemporaryDirectory
from subprocess import run, PIPE, DEVNULL
from typing import TYPE_CHECKING

from binexport.binexport2_pb2 import BinExport2
from binexport.function import FunctionBinExport
from binexport.types import FunctionType, DisassemblerBackend
from binexport.utils import logger

if TYPE_CHECKING:
    from binexport.types import Addr


class ProgramBinExport(dict):
    """
    Program class that wraps the binexport with high-level functions
    and an easy to use API. It inherits from a dict which is used to
    reference all functions based on their address.
    """

    def __init__(self, file: pathlib.Path | str):
        """
        :param file: BinExport file path
        """
        super(ProgramBinExport, self).__init__()

        self._pb = BinExport2()

        self.path: pathlib.Path = pathlib.Path(file)  #: Binexport file path

        with open(file, "rb") as f:
            self._pb.ParseFromString(f.read())
        self.mask = 0xFFFFFFFF if self.architecture.endswith("32") else 0xFFFFFFFFFFFFFFFF
        self.fun_names: dict[str, FunctionBinExport] = {}  #: dictionary function name -> name
        self.callgraph: networkx.DiGraph = networkx.DiGraph()  #: program callgraph (as Digraph)

        # Make the data refs map {instruction index -> address referred}
        # dictionary of instruction index to set of refs
        self.data_refs: dict[int, set[Addr]] = defaultdict(set)
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
                logger.error(f"Address collision for 0x{f.addr:x}")
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
                logger.error(f"Missing function address: 0x{node.address:x} ({node.type})")
                continue

            self[node.address].type = FunctionType.from_proto(node.type)
            if node.demangled_name:
                self[node.address].name = node.demangled_name
            elif node.mangled_name:
                self[node.address].name = node.mangled_name

        for edge in cg.edge:
            src = cg.vertex[edge.source_vertex_index].address
            dst = cg.vertex[edge.target_vertex_index].address
            # Unsure that both src and dst exists (Sometimes SRE like Ghidra export function that doesn't exists)
            if src in self and dst in self:
                self.callgraph.add_edge(src, dst)
                self[src].children.add(self[dst])
                self[dst].parents.add(self[src])

        # Create a map of function names for quick lookup later on
        for f in self.values():
            self.fun_names[f.name] = f

        logger.debug(
            f"total all:{count_f}, imported:{count_imp} collision:{coll} (total:{count_f + count_imp + coll})"
        )

    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self.name}>"

    @staticmethod
    def open(export_file: pathlib.Path | str) -> ProgramBinExport:
        """
        Open a BinExport file and return an instance of ProgramBinExport.

        :param export_file: BinExport file path
        :return: an instance of ProgramBinExport
        """
        return ProgramBinExport(export_file)

    @staticmethod
    def from_binary_file(
        exec_file: pathlib.Path | str,
        output_file: str | pathlib.Path = "",
        open_export: bool = True,
        override: bool = False,
        backend: DisassemblerBackend = DisassemblerBackend.IDA,
    ) -> ProgramBinExport | bool:
        """
        DEPRECATED: Use `ProgramBinExport.from_binary` instead."""
        if not open_export:
            export_path = ProgramBinExport.generate(
                exec_file=exec_file,
                output_file=output_file,
                override=override,
                backend=backend,
                timeout=600,
            )
            return export_path.exists()
        else:
            ProgramBinExport.from_binary(exec_file=exec_file, output_file=output_file,
                                     open_export=open_export, override=override, backend=backend)

    @staticmethod
    def from_binary(
        exec_file: pathlib.Path | str,
        output_file: str | pathlib.Path = "",
        override: bool = False,
        backend: DisassemblerBackend = DisassemblerBackend.IDA,
        timeout: int = 600,
    ) -> ProgramBinExport:
        """
        Generate the .BinExport file for the given program and return an instance
        of ProgramBinExport.

        .. warning:: That function requires the module ``idascript``

        :param exec_file: executable file path
        :param output_file: BinExport output file
        :param open_export: whether or not to open the binexport after export
        :param override: Override the .BinExport if already existing. (default false)
        :param backend: The backend to use. (Either 'IDA' or 'Ghidra')
        :return: an instance of ProgramBinExport if open_export is true, else boolean
                 on whether it succeeded
        """
        binexport_file = ProgramBinExport.generate(
            exec_file=exec_file,
            output_file=output_file,
            override=override,
            backend=backend,
            timeout=timeout,
        )

        # In theory if reach here export file exists otherwise an exception has been raised
        if binexport_file.exists():
            return ProgramBinExport.open(binexport_file)
        else:
            raise FileNotFoundError(f"Cannot open BinExport it does not exists: {binexport_file}")


    @staticmethod
    def generate(
        exec_file: pathlib.Path | str,
        output_file: str | pathlib.Path = "",
        override: bool = False,
        backend: DisassemblerBackend = DisassemblerBackend.IDA,
        timeout: int = 600,
    ) -> pathlib.Path:

        exec_file = pathlib.Path(exec_file)
        binexport_file = (
            pathlib.Path(output_file)
            if output_file
            else pathlib.Path(str(exec_file) + ".BinExport")
        )

        # If the binexport file already exists, do not want to override just return
        if binexport_file.exists():
            if not override:
                return binexport_file
            else:
                binexport_file.unlink(missing_ok=False)  # Remove file

        # Regenerate it!
        if backend == DisassemblerBackend.IDA:
            res = ProgramBinExport._from_ida(exec_file, binexport_file, timeout)
        elif backend == DisassemblerBackend.GHIDRA:
            res = ProgramBinExport._from_ghidra(exec_file, binexport_file, timeout)
        elif backend == DisassemblerBackend.BINARY_NINJA:
            res = ProgramBinExport._from_binary_ninja(exec_file, binexport_file, timeout)
        else:
            logger.error(f"Invalid backend '{backend}'")
            res = False
        
        # Check that it has properly been generated at the end
        match res, binexport_file.exists():
            case True, True:
                return binexport_file  # Successful!
            case False, True:
                logger.error(f"Disassembler failed but BinExport file generated: {binexport_file}")
                return binexport_file
            case True, False:
                raise FileNotFoundError(f"Disassembler succeeded but BinExport file missing: {binexport_file}")
            case False, False:
                dname = DisassemblerBackend.name
                raise FileNotFoundError(f"Disassembler {dname} failed, BinExport file missing: {binexport_file}")

    @staticmethod
    def _from_ida(
        exec_file: pathlib.Path,
        binexport_file: pathlib.Path,
        timeout: int = 600,
    ) -> bool:
        """
        Generate the .BinExport file for the given program and return an instance
        of ProgramBinExport.

        .. warning:: That function requires the module ``idascript``

        :param exec_file: executable file path
        :param binexport_file: BinExport output file
        :param timeout: Export timeout in seconds
        :return:  whether it succeeded or not
        """
        from idascript import IDA

        ida = IDA(
            exec_file,
            script_file=None,
            script_params=[
                "BinExportAutoAction:BinExportBinary",
                f"BinExportModule:{binexport_file}",
            ],
            timeout=timeout,
        )
        ida.start()
        retcode = ida.wait()

        if retcode == IDA.TIMEOUT_RETURNCODE:
            logger.warning(f"{exec_file.name} timed out after {timeout} seconds")
            return False
        
        return retcode == 0
        
    @staticmethod
    def _from_binary_ninja(
        exec_file: pathlib.Path,
        binexport_file: pathlib.Path,
        timeout: int = 600,
    ) -> bool:
        """
        Generate the .BinExport file for the given program and return an instance
        of ProgramBinExport.

        .. warning:: That function requires the module ``binaryninja``

        :param exec_file: executable file path
        :param binexport_file: BinExport output file
        :return: whether it succeeded or not
        """
        try:
            import binaryninja
        except ModuleNotFoundError as e:
            logging.error("Cannot find module python `binaryninja`. Try running BINARY_NINJA_PATH/scripts/install_api.py")
            return False

        try:
            bv = binaryninja.load(exec_file)
        except Exception as err:
            logger.warning(f'Failed to analyze {exec_file}: {err}')
            return False

        cmd = next(filter(lambda cmd: cmd.name == "BinExport", binaryninja.PluginCommand), None)
        if not cmd:
            logger.warning(f'BinExport not installed')
            return False

        ctx = binaryninja.PluginCommandContext(bv)
        cmd.execute(ctx)

        # FIXME: How to obtain the return value?
        return True

    @staticmethod
    def _from_ghidra(
        exec_file: pathlib.Path,
        binexport_file: pathlib.Path,
        timeout: int = 600,
    ) -> bool:
        """
        Generate the .BinExport file for the given program and return an instance
        of ProgramBinExport.

        .. warning:: That function requires Ghidra to be installed

        :param exec_file: executable file path
        :param binexport_file: BinExport output file
        :return: whether it succeeded or not
        """

        # Check if the GHIDRA_PATH environment variable is set
        ghidra_dir = os.environ.get("GHIDRA_PATH")
        if not ghidra_dir:
            logger.error(
                "The 'GHIDRA_PATH' environment variable is not set. Please define it to proceed."
            )
            return False

        # Check if the GHIDRA_PATH dir exists
        ghidra_dir = pathlib.Path(ghidra_dir)
        if not ghidra_dir.exists() or not ghidra_dir.is_dir():
            logger.error(f"The path specified in 'GHIDRA_PATH' does not exist: {ghidra_dir}")
            return False

        # Small script to do the binexport
        ghidra_script = dedent(
            f"""
            from java.io import File
            try:
                from com.google.security.binexport import BinExportExporter
            except ImportError:
                print("BinExport plugin is not installed")
                exit()
            
            exporter = BinExportExporter() #Binary BinExport (v2) for BinDiff
            exporter.export(File("{binexport_file.absolute()}"), currentProgram, currentProgram.getMemory(), monitor)
            """
        )

        # Do everything in a TemporaryDirectory to avoid polluting the user filesystem
        with TemporaryDirectory() as tmpdirname:
            tmpdir = pathlib.Path(tmpdirname)
            ghidra_script_path = tmpdir / "BinExportGhidraScript.py"
            with open(ghidra_script_path, "w") as fp:
                fp.write(ghidra_script)

            proc = run(
                [
                    str(ghidra_dir / "support" / "analyzeHeadless"),
                    tmpdirname,
                    "tmpproj",
                    "-scriptPath",
                    tmpdirname,
                    "-postScript",
                    str(ghidra_script_path),
                    "-import",
                    str(exec_file.absolute()),
                ],
                stdout=PIPE,
                stderr=DEVNULL,
                timeout=timeout,
            )

            if proc.returncode != 0:
                logger.warning(
                    f"{exec_file.name} failed to export [ret:{proc.returncode}, binexport:{binexport_file.exists()}]"
                )
                return False

            elif b"BinExport plugin is not installed" in proc.stdout:
                # Using exit(code) inside ghidra script do not propagate so we need to search through
                # the script output to detect an error
                logger.warning("BinExport plugin not found, please install it!")
                return False

        # if reach here assume running went fine.
        return True

    @property
    def proto(self) -> BinExport2:
        """
        Returns the protobuf object associated to the program
        """
        return self._pb

    @property
    def name(self) -> str:
        """
        Return the name of the program (as exported by binexport)
        """
        return self.proto.meta_information.executable_name

    @property
    def architecture(self) -> str:
        """
        Returns the architecture suffixed with address size ex: x86_64, x86_32
        """

        return self.proto.meta_information.architecture_name
