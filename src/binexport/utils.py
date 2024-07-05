from __future__ import annotations
import logging
from collections.abc import Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binexport.binexport2_pb2 import Binexport2
    from binexport.types import Addr


def get_instruction_address(pb: "BinExport2", inst_idx: int) -> Addr:
    """
    Low level binexport protobuf function to return the address of an instruction
    given its index in the protobuf.

    :param pb: binexport protobuf object
    :param inst_idx: index of the instruction
    :return: address of the instruction
    """

    inst = pb.instruction[inst_idx]
    if inst.HasField("address"):
        return inst.address
    else:
        return backtrack_instruction_address(pb, inst_idx)


def backtrack_instruction_address(pb: BinExport2, idx: int) -> int:
    """
    Low level function to backtrack the instruction array for instruction that
    does not have the address field set

    :param pb: binexport protobuf object
    :param idx: index of the instruction
    :return: address of the instruction
    """

    tmp_sz = 0
    tmp_idx = idx
    if tmp_idx == 0:
        return pb.instruction[tmp_idx].address
    while True:
        tmp_idx -= 1
        tmp_sz += len(pb.instruction[tmp_idx].raw_bytes)
        if pb.instruction[tmp_idx].HasField("address"):
            break
    return pb.instruction[tmp_idx].address + tmp_sz


def get_basic_block_addr(pb: BinExport2, bb_idx: int) -> Addr:
    """
    Low level function to retrieve the basic block address from its index.
    The function takes the first instruction of the basic block and retrieve
    its address.

    :param pb: binexport protobuf object
    :param bb_idx: index of the basic block
    :return: address of the basic block in the program
    """

    inst = pb.basic_block[bb_idx].instruction_index[0].begin_index
    return get_instruction_address(pb, inst)


def instruction_index_range(rng: Binexport2.BasicBlock.IndexRange) -> Iterator[int]:
    """
    Low level function to iterate over the indices of a protobuf IndexRange.

    :param rng: binexport IndexRange object
    :return: iterator over the indices
    """
    return range(rng.begin_index, (rng.end_index if rng.end_index else rng.begin_index + 1))


# Main logger object
logger = logging.getLogger("python-binexport")
