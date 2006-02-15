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
from pyroman import firewall
from util import Util

class Interface:
	"""
	Interfaces (or -groups) are used to filter based on physical networks
	"""
	def __init__(self, name, iface, loginfo):
		"""
		Create a new interface

		name -- name for this interface (-group)
		iface -- kernel interface names, e.g. "eth0 eth1"
		"""
		if name == "" or not Util.verify_name(name):
			raise "Interface lacking a valid name (name: %s, iface: %s) at %s" \
				% (name, iface, loginfo)
		if firewall.interfaces.has_key(name):
			raise "Duplicate interface specification: %s at %s" % (name, loginfo)
		if iface == "":
			raise "Interface definition lacking kernel interfaces: %s at %s" \
				% (name, loginfo)
		self.name = name
		self.iface = Util.splitter.split(iface)
		self.loginfo = loginfo

		# register with firewall
		firewall.interfaces[name] = self

	def get_filter(self, dir):
		"""
		Generate filter rules for this interface by generating a list of
		filter rules for all source specifications

		dir -- either "d" or "s" for destination filter or source filter
		"""
		idir = None
		if dir == "d":
			idir = "o"
		elif dir == "s":
			idir = "i"
		else:
			raise "Unknown direction specified: %s" % dir
		# when necessary, turn around filter directions
		result = []
		for i in self.iface:
			if i != "":
				result.append( "-%s %s" % (idir, i) )
		return result

	def prepare(self):
		"""
		Prepare interface definition for generation
		Nothing to do here for now
		"""
		pass

	def verify(self):
		"""
		Verify that the interface definition is complete, in addition to the
		checks at creation time. (Currenlty, no additional checks are done.)
		"""
		# no additional checks yet
		pass
