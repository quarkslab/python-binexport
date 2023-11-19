# Python-Binexport

``python-binexport`` is a python module aiming to give a friendly interface to load
and manipulate binexport files.

## What is binexport ?

Binexport is a ``protobuf`` format used by Bindiff to extract IDA database and
to process them outside. It gives a very optimizated (in size) representation
of the program.

## Dependencies

Python-binexport can load any .BinExport files generated from the supported disassemblers
IDA, Ghidra and Binary Ninja.

However to perform the export with ``binexporter`` or from the API ``ProgramBinexport.from_binary_file()``
the IDA plugin must be installed as it is the only supported at the moment. For that it has to be [installed first from the github page](https://github.com/google/binexport).
To use the feature python-binexport requires IDA >=7.2 (as it calls the ``BinExportBinary`` IDC function). 

> [!WARNING]
> If you export files from python-binexport make sure the IDA Pro binexport plugin is properly installed
> and works when running it manually before trying to use it from the python library (it can hang if not properly installed).


> [!NOTE]
> The possibility to export files using Ghidra, or Binary Ninja from python-binexport
> might be supported in the future.


## Installation

    pip install python-binexport



## Python module usage

The main intended usage of ``python-binexport`` is as a python module.
The main entry point is the class ``ProgramBinExport`` which triggers the
loading of the whole file. Here is a snippet to iterate on every expression
of every instruction in the program:

```python
from binexport import ProgramBinExport

p = ProgramBinExport("myprogram.BinExport")
for fun_addr, fun in p.items():
    with fun:  # Preload all the basic blocks
        for bb_addr, bb in fun.items():
            for inst_addr, inst in bb.instructions.items():
                for operand in inst.operands:
                    for exp in operand.expressions:
                        pass  # Do whatever at such deep level
```

Obviously ``ProgramBinExport``, ``FunctionBinExport``, ``InstructionBinExport`` and ``OperandBinExport``
all provides various attributes and method to get their type, and multiple other infos.

> If the module ``idascript`` is installed you can directly generate a BinExport
> file using the ``Program.from_binary_file`` static method.

## Command line usage

The executable script ``binexporter`` provides a very basic utility
to export a BinExport file straight from the command line *(without
having to launch IDA etc..)*. This is basically a wrapper for ``Program.from_binary_file``.
