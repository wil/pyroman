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
import re, inspect, socket
from exception import PyromanException

class Util:
	"""
	Some utility functions for the firewall system
	"""
	# regexp used for splitting strings
	splitter = re.compile("(?:,\s*|\s+)")
	# regexp to ignore lines in manual rules
	ignoreline = re.compile("^\s*(#|$)")
	# nicknames may only contain these chars
	namefilter = re.compile("^[a-zA-Z0-9]+$")
	namefilter_service = re.compile("^[a-zA-Z0-9/]+$")

	def get_callee(depth=3):
		"""
		Return information about the calling function
		"""
		frame = inspect.stack(depth)
		return "%s:%d" % (frame[depth-1][1], frame[depth-1][2])
	get_callee = staticmethod(get_callee)

	def verify_ip4(ip):
		"""
		Verify that the given string is an IPv4 address
		"""
		try:
			socket.inet_pton(socket.AF_INET, ip)
			return True
		except socket.error:
			return False
	verify_ip4 = staticmethod(verify_ip4)

	def verify_ip6(ip):
		"""
		Verify that the given string is an IPv6 address
		"""
		try:
			socket.inet_pton(socket.AF_INET6, ip)
			return True
		except socket.error:
			return False
	verify_ip6 = staticmethod(verify_ip6)

	def verify_ip4net(ip):
		"""
		Verify that the given string describes an IPv4 network
		"""
		l = ip.split("/", 1)
		if len(l) == 0:
			return False
		if not Util.verify_ip4(l[0]):
			return False
		if len(l) == 1:
			return True
		n = int(l[1])
		return (n >= 0) and (n <= 32)
	verify_ip4net = staticmethod(verify_ip4net)

	def verify_ip6net(ip):
		"""
		Verify that the given string describes an IPv6 network
		"""
		l = ip.split("/", 1)
		if len(l) == 0:
			return False
		if not Util.verify_ip6(l[0]):
			return False
		if len(l) == 1:
			return True
		n = int(l[1])
		return (n >= 0) and (n <= 128)
	verify_ip6net = staticmethod(verify_ip6net)

	def verify_ip(ip):
		"""
		Verify that the given string is an IPv4 or IPv6 address
		"""
		return Util.verify_ip4(ip) or Util.verify_ip6(ip)
	verify_ip = staticmethod(verify_ip)

	def verify_ipnet(ip):
		"""
		Verify that the given string is an IPv4 or IPv6 address
		"""
		return Util.verify_ip4net(ip) or Util.verify_ip6net(ip)
	verify_ipnet = staticmethod(verify_ipnet)

	def verify_name(name, servicename=False):
		"""
		Verify that a name only contains a certain set of characters
		to avoid problems with rule names derived from it.

		name -- name to be checked
		servicename -- Set to true to allow the / char additionally
		"""
		if servicename:
			m = Util.namefilter_service.match(name)
			if m:
				return True
		else:
			m = Util.namefilter.match(name)
			if m:
				return True
		return False
	verify_name = staticmethod(verify_name)

	def compare_versions(ver1, ver2):
		"""
		Compare to version numbers
		returns True if ver1 is less or equal to ver2

		ver1 -- first version number
		ver2 -- second version number
		"""
		def compsplit(s):
			"""
			Split a version number component into a pair of (int,str)
			"""
			if not s[0].isdigit():
				return (None, s)
			for i in range(1,len(s)):
				if not s[i].isdigit():
					return (int(s[:i]),s[i:])
			return (int(s),"")

		v1c = ver1.split(".")
		v2c = ver2.split(".")
		minl = min(len(v1c),len(v2c))
		for i in range(minl):
			(v1, v1s) = compsplit(v1c[i])
			(v2, v2s) = compsplit(v2c[i])
			# one has digits, one hasn't?
			if not v1: return -1
			if not v2: return +1
			if v1 != v2:
				assert(cmp(v1,v2) != 0)
				return cmp(v1, v2)
			# compare remaining string
			c = cmp(v1s,v2s)
			if c != 0: return c
		if len(v1c) < len(v2c): return -1
		if len(v1c) > len(v2c): return +1
		return 0
	compare_versions = staticmethod(compare_versions)
