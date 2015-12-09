README for mkgetopt
===================

mkgetopt.py generates ANSI C command line parsing routines that uses
``getopt_long()``. It aims to remove the tedium of parsing command
line options in various programs.

It reads a text file containing descriptions of the command line
options and generates corresponding .c, and .h files. These
generated files have no other dependency other than ``getopt_long()``
and ``libc``.


Requirements
------------
Python 2.7.x

Installation
------------
Unix like systems (including OS X Darwin)::

   ./install.sh

Windows:

   - copy mkgetopt.py to some directory in ``%PATH``
   - copy the mkgetopt-manual.txt to a directory where you can find
     it in the future (for reference)

If your system doesn't have a functional ``getopt_long()`` - use the
version provided here. The bundled version of ``getopt_long()`` is
from NetBSD with minor changes for ANSI-fication, and is distributed
under the terms described at the top of ``getopt_long.h`` and
``getopt_long.c``.

Details
=======
Read the reStructured Text file *mkgetopt-manual.txt*. If you have
docutils installed, you can generate a PDF of the .txt file and read
it at your leisure.

The same text file is converted to a manpage and is available as
mkgetopt.1; on Unix like systems, this is installed as
*mkgetopt.py.1.gz"


.. vim:ft=rst:sw=4:ts=4:notextmode:expandtab:
