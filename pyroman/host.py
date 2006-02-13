#Copyright (c) 2005 Erich Schubert erich@debian.org

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

class Host:
	"""
	Represents a single host or a subnet with the same permissions
	"""
	def __init__(self, name, ip, iface, hostname, loginfo):
		"""
		Create a new host object, with the given name, IP specification and interface

		name -- Nickname for the host
		ip -- IP specification for the host or subnet (e.g. "127.0.0.1 10.0.0.0/24")
		iface -- Interface nickname this is connected to (only one!)
		"""
		# verify and store name
		if name == "" and not Util.verify_name(name):
			raise "Host '%s' lacking a valid name at %s" \
				% (name, iface, loginfo)
		if firewall.hosts.has_key(name):
			raise "Duplicate host specification: '%s' at %s" % (name, loginfo)
		self.name = name
		# verify and store IPs
		if ip == "":
			raise "Host '%s' definition lacking IP address at %s" % (name, loginfo)
		self.ip = Util.splitter.split(ip)
		for i in self.ip:
			if not Util.verify_ip(i):
				raise "IP specification '%s' invalid for host '%s' at %s" \
					% (i, name, loginfo)
		# verify and store interface
		self.iface = iface
		if iface == "":
			raise "Host definition '%s' lacking kernel interfaces at %s" \
				% (name, loginfo)
		# store "real" hostname (which may be longer than nick)
		# this is used for "localhost detection"
		self.hostname = hostname
		# store loginfo
		self.loginfo = loginfo
		# register with firewall
		firewall.hosts[name] = self

	def get_filter(self, dir):
		"""
		Generate filter rules for this host by generating a list of
		filter rules for all source specifications

		dir -- either "d" or "s" for destination filter or source filter
		"""
		# when necessary, turn around filter directions
		result = []
		for i in self.ip:
			# for the "any" IP we don't need to print a parameter
			if i == "0.0.0.0/0":
				result.append("")
			elif i != "":
				result.append( "-%s %s" % (dir, i) )
		return result
	
	def islocalhost(self):
		"""
		Check if the host is localhost by comparing the hostname given to the
		hostname of the current machine
		"""
		return self.hostname == firewall.hostname

	def prepare(self):
		"""
		Prepare host for compilation
		"""
		# lookup interface
		# this was verified in the verify run already
		self.iface = firewall.interfaces[self.iface]

	def verify(self):
		"""
		Verify that the host is properly specified.
		Verifies that the interface given was properly defined.
		"""
		if not firewall.interfaces.has_key(self.iface):
			raise "Host '%s' is assigned interface '%s' which is not defined at %s" \
				% (self.name, self.iface, self.loginfo)
