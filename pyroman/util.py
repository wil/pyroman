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
import re, inspect

class Util:
	"""
	Some utility functions for the firewall system
	"""
	# regexp used for splitting strings
	splitter = re.compile("(?:,\s*|\s+)")
	# regexp to ignore lines in manual rules
	ignoreline = re.compile("^\s*(#|$)")
	# regexp to verify an IP with optional netmask
	ipmask = re.compile("^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)(/([0-9.]+))?$")
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

	def verify_ip(ip, nonet=False):
		"""
		Verify that a certain string is an IP address

		ip -- string to be verified
		nonet -- if set to True, do not allow subnet specifications
		"""
		m = Util.ipmask.match(ip)
		if m is None:
			return False
		for i in [1,2,3,4]:
			if int(m.group(i)) < 0 or int(m.group(i)) > 255:
				return False
		if not m.group(5):
			return True
		if nonet:
			return False
		if m.group(6).isdigit() or ipmask.match(m.group(6)):
			return True
		return False
	verify_ip = staticmethod(verify_ip)

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
