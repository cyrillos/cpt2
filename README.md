cpt2
====

An utility to convert OpenVZ checkpoint files to CRIU format.

Building
========

cpt2 highly depends on source code shipped with CRIU user-space tool.
An easiest way to obtain it -- just to clone it as

	# git clone git://git.criu.org/crtools.git

Once crtools code cloned one can start building procedure.

	# CRIUDIR=/path/to/crtools/sources make

Warning
=======
The project is in early alfa stage, for test purposes only!
