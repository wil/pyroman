#!/usr/bin/python
import glob
# usercommands, the Firewall class and the firewall object
# should be available to user rules
from pyroman.pyroman import Firewall, firewall
from pyroman.commands import *

# load user rules alphabetically
rfiles = glob.glob("rules/*.py")
rfiles.sort()
for nam in rfiles:
	execfile(nam)

# do some consistency checks
firewall.verify()
# generate...
firewall.generate()
# dump the rules
#firewall.print_rules()
# ... or execute
firewall.execute_rules()
