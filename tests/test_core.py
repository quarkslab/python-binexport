import glob
from itertools import islice

from binexport import ProgramBinExport


def test_from_protobuf():
    """Regression tests for loading from protobuf"""

    for filename in glob.glob("tests/data/*"):
        print(f"Analyzing {filename}...")
        p = ProgramBinExport(filename)
        for func in p.values():
            for bb in islice(func.blocks.values(), 0, 2):
                for instr in islice(bb.instructions.values(), 0, 2):
                    for op in instr.operands:
                        for expr in op.expressions:
                            pass
