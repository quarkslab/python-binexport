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


def export_job(ingress, egress, backend) -> bool:
    while True:
        try:
            file = ingress.get(timeout=0.5)
            res = ProgramBinExport.from_binary_file(
                file.as_posix(), backend=backend, open_export=False
            )
            egress.put((file, res))
        except Exception as e:
            # Might not be printed as triggered withing a fork
            logger.error(traceback.format_exception(e).decode())
            egress.put((file, e))
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            break


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-i",
    "--ida-path",
    type=click.Path(exists=True),
    default=None,
    help="IDA Pro installation directory",
)
@click.option(
    "-g",
    "--ghidra-path",
    type=click.Path(exists=True),
    default=None,
    help="Ghidra installation directory",
)
@click.option(
    "-b",
    "--binja",
    is_flag=True,
    help="Use Binary Ninja backend",
)
@click.option("-t", "--threads", type=int, default=1, help="Thread number to use")
@click.option("-v", "--verbose", count=True, help="To activate or not the verbosity")
@click.option("--stop-on-error", is_flag=True, default=False, help="Stop on error")
@click.argument("input_file", type=click.Path(exists=True), metavar="<binary file|directory>")
def main(ida_path: str,
         ghidra_path: str,
         binja: bool,
         input_file: str,
         threads: int,
         verbose: bool,
         stop_on_error: bool) -> None:
    """
    binexporter is a very simple utility to generate a .BinExport file
    for a given binary or a directory. It all open the binary file and export the file
    seamlessly.

    :param ida_path: Path to the IDA Pro installation directory
    :param input_file: Path of the binary to export
    :param threads: number of threads to use
    :param verbose: To activate or not the verbosity
    :param stop_on_error: Stop if any of the worker raises an exception
    :return: None
    """

    logging.basicConfig(format="%(message)s", level=logging.DEBUG if verbose else logging.INFO)

    if binja:
        backend = DisassemblerBackend.BINARY_NINJA
    elif ghidra_path:
        os.environ["GHIDRA_PATH"] = Path(ghidra_path).absolute().as_posix()
        backend = DisassemblerBackend.GHIDRA
    else:
        if ida_path:
            os.environ["IDA_PATH"] = Path(ida_path).absolute().as_posix()
        backend = DisassemblerBackend.IDA

    root_path = Path(input_file)

    manager = Manager()
    ingress = manager.Queue()
    egress = manager.Queue()
    pool = Pool(threads)

    # Launch all workers
    for _ in range(threads):
        pool.apply_async(export_job, (ingress, egress, backend))

    # Pre-fill ingress queue
    total = 0
    for file in recursive_file_iter(root_path):
        ingress.put(file)
        total += 1

    logger.info(f"Start exporting {total} binaries with {backend} backend")

    i = 0
    while True:
        item = egress.get()
        i += 1
        path, res = item

        # Check if the result is an exception
        if isinstance(res, Exception):
            logger.error(f"Error while processing {path}: {res}")
            if stop_on_error:
                logger.error(traceback.format_exception(res).decode())
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
