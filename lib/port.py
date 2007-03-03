#Copyright (c) 2007 Erich Schubert erich@debian.org

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
import re, socket
from exception import PyromanException

class PortInvalidSpec(Exception):
	"""
	Exception class for invalid port specifications
	"""
	def __init__(self, err, spec):
		"""
		Create new InvalidPortSpecification
		"""
		self.err = err
		self.spec = spec
	def __str__(self):
		"""
		Return error message
		"""
		return self.err

class Port:
	"""
	This class represents a single tcp/udp/icmp port
	(or the whole protocol!)
	It's instantiated from a string, which is parsed and checked
	and it contains a to_filter method to generate an iptables filter
	"""

	# Split and verify syntax of statement
	preg  = re.compile("^(?:([a-z0-9\-]+|[0-9]+(?:\:[0-9]+)?)(?:/))?(tcp|udp|icmp)$")
	# verify port range
	prreg = re.compile("^([0-9]+:)?[0-9]+$")

	def __init__(self, spec):
		"""
		Initialize port from a specification string of the type "123/tcp"

		If the string is not parseable, PortInavlidSpec is raised
		"""
		self.proto = ""
		self.port = None
		# if a spec is given, process
		if spec != "":
			m = self.preg.match( spec )
			if m is None:
				raise PortInvalidSpec("Invalid port specification: %s" % spec, spec)
			self.port = m.group(1)
			self.proto = m.group(2)

			# if it's a named port, verify it's resolveable...
			if not self.prreg.match(self.port) and self.proto in ["udp", "tcp"]:
				try:
					socket.getservbyname(self.port, self.proto)
				except socket.error:
					raise PortInvalidSpec("Port %s/%s not defined in /etc/services" % (self.port, self.proto), spec)

	def get_filter_proto(self):
		"""
		Return iptables rule to filter for this protocol as string
		"""
		if self.proto:
			return "-p %s" % self.proto

	def get_filter_port(self, dir):
		"""
		Return iptables rule to filter for this specific port as string
		An appropriate protocol filter needs to be added, too (use the
		get_filter_proto method for that). Note that source and destination
		filters only make sense if they use the same protocol!

		dir -- direction ("d" for destination or "s" for source filter)
		"""
		if not self.port:
			return ""
		
		if self.proto in ["tcp", "udp"]:
			return "--%sport %s" % (dir, self.port)
		elif self.proto == "icmp":
			# ICMP doesn't have source ports
			if dir == "d":
				return "--icmp-type %s" % self.port
			else:
				return ""
		else:
			raise PyromanException("Unknown protocol: %s" % self.proto)
