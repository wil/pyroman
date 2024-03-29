#Copyright (c) 2011 Erich Schubert erich@debian.org

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
from pyroman import Firewall
from util import Util
from port import Port, PortInvalidSpec
from exception import PyromanException

class Service:
	"""
	A service can consist of several source and destination ports.
	by including other services, any restriction on source-destination
	port combinations is possible, also with different protocols.
	"""
	def __init__(self, name, sports="", dports="", include="", loginfo=""):
		"""
		Create new service object with string parameters

		sports -- source port specifications like "www/tcp dns/udp"
		dports -- destination port specifications
		include -- include rules for other services to be included/aliased
		loginfo -- reference line number for user error messages
		"""
		if name == "" or not Util.verify_name(name, servicename=True):
			raise PyromanException("service lacking a proper name: '%s' at %s" \
				% (name, loginfo))
		if Firewall.services.has_key(name):
			raise PyromanException("Duplicate service specification: '%s' at %s" % (name, loginfo))
		if sports == "" and dports == "" and include == "" and (name != "ANY"):
			raise PyromanException("service specification invalid: '%s' at %s" % (name, loginfo))

		self.name = name
		self.loginfo = loginfo
		try:
			self.sports = map( lambda p: Port(p), Util.splitter.split(sports) )
			self.dports = map( lambda p: Port(p), Util.splitter.split(dports) )
		except PortInvalidSpec, p:
			raise PyromanException("Service '%s' contains invalid port spec '%s' at %s: %s" \
				% (name, p.spec, loginfo, p.err))
		# store includes, cannot be verified yet
		self.include = []
		if include:
			self.include = Util.splitter.split(include)
		# register with firewall object
		Firewall.services[name] = self

	def get_filter(self, dir, v4v6):
		"""
		Generate filter rules for this service by generating a list of
		filter rules for all source and destination port combinations

		dir -- either "d" or "s" for destination filter or source filter
		v4v6 -- either 4 or 6 for IPv4 or IPv6
		"""
		# set 1 and 2 to source/dest filter characters
		if dir == "d":
			dir1 = "s"
			dir2 = "d"
		elif dir == "s":
			dir1 = "d"
			dir2 = "s"
		else:
			raise PyromanException("Invalid direction specified: %s" % dir)
		result = []
		for sp in self.sports:
			if v4v6 == 4 and not sp.forIPv4(): continue
			if v4v6 == 6 and not sp.forIPv6(): continue
			for dp in self.dports:
				if v4v6 == 4 and not dp.forIPv4(): continue
				if v4v6 == 6 and not dp.forIPv6(): continue
				# only generate rules when source and destination protocol match
				if not sp.proto or not dp.proto or sp.proto == dp.proto:
					f1 = ""
					if sp.proto:
						f1 = sp.get_filter_proto() + " "
					elif dp.proto:
						f1 = dp.get_filter_proto() + " "
					f2 = sp.get_filter_port(dir1)
					f3 = dp.get_filter_port(dir2)
					if f2 != "" or f3 != "":
						result.append( f1 + " " + f2 + " " + f3 )

		for i in self.include:
			result.extend( i.get_filter(dir, v4v6) )
		return result

	def prepare(self):
		"""
		Prepare for generation run by looking up includes
		"""
		# look up includes, was verified in verify run
		self.include = map( lambda s: Firewall.services[s], self.include )
	
	def verify(self):
		"""
		Verify that the service doesn't try to include a service which is not
		defined. Future versions might want to add a loop detection.
		"""
		for i in self.include:
			if not i == "" and not Firewall.services.has_key(i):
				raise PyromanException("Service '%s' tries to include undefined '%s' at %s" \
					% (self.name, i, self.loginfo))
