#!/usr/bin/env python3
# coding: utf-8

import logging
import traceback
from pathlib import Path
from typing import Generator

import magic
import click
import queue
import os

from multiprocessing import Pool, Queue, Manager

from idascript import IDA_PATH_ENV, get_ida_path
from binexport import ProgramBinExport
from binexport.utils import logger
from binexport.types import DisassemblerBackend

BINARY_FORMAT = {
    "application/x-dosexec",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-executable",
    "application/x-pie-executable",
}

EXTENSIONS_WHITELIST = {"application/octet-stream": [".dex"]}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=300)

class Bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def recursive_file_iter(p: Path) -> Generator[Path, None, None]:
    if p.is_file():
        mime_type = magic.from_file(str(p), mime=True)
        if mime_type not in BINARY_FORMAT and p.suffix not in EXTENSIONS_WHITELIST.get(
            mime_type, []
        ):
            pass
        else:
            yield p
    elif p.is_dir():
        for f in p.iterdir():
            yield from recursive_file_iter(f)


def export_job(ingress, egress, backend: DisassemblerBackend) -> None:
    while True:
        try:
            file = ingress.get(timeout=0.5)
            res = ProgramBinExport.generate(file.as_posix(), backend=backend)
            egress.put((file, res))
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            break
        except Exception as e:
            # Might not be printed as triggered withing a fork
            logger.error(traceback.format_exception(e))
            egress.put((file, e))


def check_disassembler_availability(disass: DisassemblerBackend, disass_path: str) -> bool:
    """
    Check if the disassembler is available in the system.
    It also set the necessary environment variables.

    :param disass: Disassembler backend to check
    :param disass_path: Path of the disassembler (if not in PATH)
    :return: True if the disassembler is available, False otherwise
    """
    if disass == DisassemblerBackend.IDA:
        if disass_path:
            ida_path = Path(disass_path)
            os.environ[IDA_PATH_ENV] = str(ida_path)
        try:
            return bool(get_ida_path())
        except ImportError:
            logger.error("Cannot import idascript python module")
            return False
    
    elif disass == DisassemblerBackend.GHIDRA:
        if disass_path:
            ghidra_path = Path(disass_path)
            os.environ["GHIDRA_PATH"] = disass_path
            return ghidra_path.exists()
        else:
            logger.error(f"Ghidra path {disass_path} does not exist")
            return False
    
    elif disass == DisassemblerBackend.BINARY_NINJA:
        try:
            import binaryninja # type: ignore
        except ImportError:
            logger.error("Cannot import binaryninja python module")
            return False
    else:
        logger.error(f"Unknown disassembler {disass}")
        return False
    return True


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-d",
    "--disassembler",
    type=click.Choice([x.name.lower() for x in DisassemblerBackend], case_sensitive=False),
    default="ida",
    help="Disassembler to use",
)
@click.option(
    "--disass-path",
    type=click.Path(exists=True),
    default="",
    help="Path of the disassembler (dir or binary for IDA, dir for Ghidra)" \
    "(if not provided search $PATH or environment variable IDA_PATH, GHIDRA_PATH)",
)
@click.option("-t", "--threads", type=int, default=1, help="Thread number to use")
@click.option("-v", "--verbose", count=True, help="To activate or not the verbosity")
@click.option("--stop-on-error", is_flag=True, default=False, help="Stop on error")
@click.argument("input_file", type=click.Path(exists=True), metavar="<binary file|directory>")
def main(disassembler: str,
         disass_path: str,
         input_file: str,
         threads: int,
         verbose: bool,
         stop_on_error: bool) -> None:
    """
    binexporter is a very simple utility to generate a .BinExport file
    for a given binary or a directory. It opens all binary files and export
    the them seamlessly.
    """

    logging.basicConfig(format="%(message)s", level=logging.DEBUG if verbose else logging.INFO)

    # Get enum from string
    engine = DisassemblerBackend[disassembler.upper()]

    # Check disassembler availability
    if not check_disassembler_availability(engine, disass_path):
        logger.error(f"Error trying to find disassembler {engine.name.lower()}")
        return

    root_path = Path(input_file)

    manager = Manager()
    ingress = manager.Queue()
    egress = manager.Queue()
    pool = Pool(threads)

    # Launch all workers
    for _ in range(threads):
        pool.apply_async(export_job, (ingress, egress, engine))

    # Pre-fill ingress queue
    total = 0
    for file in recursive_file_iter(root_path):
        ingress.put(file)
        total += 1

    logger.info(f"Start exporting {total} binaries with {engine.name} backend")

    i = 0
    while True:
        item = egress.get()
        i += 1
        path, res = item

        # Check if the result is an exception
        if isinstance(res, Exception):
            logger.error(f"Error while processing {path}: {res}")
            if stop_on_error:
                logger.error(traceback.format_exception(res))
                pool.terminate()
                break
            else:
                res = False # set to false and just print KO
        
        # Print the result
        if res:
            pp_res = Bcolors.OKGREEN + "OK" + Bcolors.ENDC
        else:
            pp_res = Bcolors.FAIL + "KO" + Bcolors.ENDC
        logger.info(f"[{i}/{total}] {str(path) + '.BinExport'} [{pp_res}]")
        if i == total:
            break

    pool.terminate()


if __name__ == "__main__":
    main()
