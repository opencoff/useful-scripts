README for mkgetopt
===================

mkgetopt.py is a simple Python script to generate command line
parsing routines that use ``getopt_long()``. It is designed to
remove the tedium of having to write the same code over and over
again. 

It reads an text file containing descriptions of the command line
options and generates corresponding .c, and .h files.

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


Details
=======
Read the reStructured Text file *mkgetopt-manual.txt*. If you have
docutils installed, you can generate a PDF of the .txt file and read
it at your leisure.

The same text file is converted to a manpage and is available as
mkgetopt.1; on Unix like systems, this is installed as
*mkgetopt.py.1.gz"


.. vim:ft=rst:sw=4:ts=4:notextmode:expandtab:
