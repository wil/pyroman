#!/usr/bin/python
""" Pyroman, an iptables firewall configuration tool """
# where the pyroman libraries are found - e.g. /usr/share/pyroman
library_path = "./lib"
# where the rules are located - e.g. /etc/pyroman
rules_path = "./examples"
# timeout for the "safe" mode invocation
safe_timeout = 30

#Copyright (c) 2006 Erich Schubert erich@debian.org

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
import sys, glob, os

# path to the main pyroman code
sys.path.insert(0, library_path)

# usercommands, the Firewall class and the firewall object
# should be available to user rules
from pyroman import Firewall
from commands import *

# When given the "safe" parameter, setup a timeout.
if len(sys.argv) > 1 and sys.argv[1] == "safe":
	Firewall.timeout = safe_timeout

# load user rules alphabetically
rfiles = glob.glob(os.path.join(rules_path,"*.py"))
rfiles.sort()
for nam in rfiles:
	execfile(nam)

# do some consistency checks
Firewall.verify()
# generate...
Firewall.generate()
# execute firewall
Firewall.execute_rules()
