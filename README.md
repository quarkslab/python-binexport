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

Optionallt it requires ``idascript`` (https://gitlab.qb/rdavid/idascript) to directly
generating the binexport files.
