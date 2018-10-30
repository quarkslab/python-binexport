# Python Binexport

``python-binexport`` is a python module aiming to give a friendly interface to load
and manipulate binexport files.

What is binexport ?
-------------------

Binexport is a ``protobuf`` format used by Bindiff to extract IDA database and
to process them outside. It gives a very optimizated (in size) representation
of the program.

Dependencies
------------

Python binexport solely relies on:

* protobuf
* networkx *(to represent the call graph)*
* click *(for ``binexporter``)*
* python-magic *(for ``binexporter``)*


Optionallt it requires ``idascript`` (https://gitlab.qb/rdavid/idascript) to directly
generating the binexport files.


Usage as a python module
------------------------

The main intended usage of ``python-binexport`` is as a python module.
The main entry point is the class ``ProgramBinExport`` which triggers the
loading of the whole file. Here is a snippet to iterate on every expression
of every instruction in the program:

```python
from binexport import ProgramBinExport

p = ProgramBinExport("myprogram.BinExport")
for fun_addr, fun in p.items():
    for bb in fun:
        for inst in bb:
            for operand in inst.operands:
                for exp in operand.expressions:
                    pass  # Do whatever at such deep level

```

Obviously ``ProgramBinExport``, ``FunctionBinExport``, ``InstructionBinExport`` and ``OperandBinExport``
all provides various attributes and method to get their type, and multiple other infos.

> If the module ``idascript`` is installed you can directly generate a BinExport
> file using the ``Program.from_binary_file`` static method.

Usage as a command line
-----------------------

The executable script ``binexporter`` provides a very basic utility
to export a BinExport file straight from the command line *(without
having to laucnh IDA etc..)*. This is basically a wrapper for ``Program.from_binary_file``.