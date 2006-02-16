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
from pyroman import Firewall
from service import Service
from port import PortInvalidSpec
from chain import Chain

class Rule:
	"""
	A rule is an allow/drop/reject statement for a certain combination of hosts
	and services. They are processed in sequence, and grouped into chains with
	similar filters to increase efficiency.
	"""
	def __init__(self,target,server,client,service,loginfo):
		"""
		Create a new rule, with given action, source, destination and service

		target -- the action if the rule matches, e.g. do_accept
		server -- host the packets are addressed to
		client -- host the packets originate from
		service -- service (i.e. ports) the packages use
		loginfo -- user information about origin of this rule for errors
		"""
		# store parameters for later use
		self.target = target
		self.server = server
		self.client = client
		self.service = service
		self.loginfo = loginfo

		if not server and not client:
			raise "Rules need at least a server or a client at %s" % loginfo

		# a complete verification will be done when all user files have been
		# processed (and thus no new services can be added any more)

	def generate(self):
		"""
		Generate iptables-rules for this firewall rule.
		"""
		inface = ""
		outface = ""
		# look up interfaces
		if self.client:
			inface = self.client.iface
		if self.server:
			outface = self.server.iface

		if inface == outface \
			and not self.client.islocalhost() \
			and not self.server.islocalhost():
			return

		chain = Chain.get_chain(inface, outface, self.client, self.server, self.loginfo)

		vrules = [""]
		if self.service:
			vrules = self.service.get_filter("d")
		for vr in vrules:
			chain.append("%s -j %s" % (vr, self.target), self.loginfo)

	def prepare(self):
		"""
		Prepare object by replacing string references with object pointers
		"""
		# already checked in verify run.
		if self.server != "":
			self.server = Firewall.hosts[self.server]
		else:
			self.server = None
		# already checked in verify run.
		if self.client != "":
			self.client = Firewall.hosts[self.client]
		else:
			self.client = None
		# already checked in verify run.
		if self.service != "":
			self.service = Firewall.services[self.service]
		else:
			self.service = None

	def verify(self):
		"""
		Run some basic verifications on the rule
		This will e.g. verify that the hosts referred to do exist, services are
		properly defined and so on.
		"""
		# verify server name given
		if self.server != "":
			if not Firewall.hosts.has_key(self.server):
				raise "Rule refers to unknown host as server: '%s' at %s" \
					% (self.server, self.loginfo)
		# verify client name given
		if self.client != "":
			if not Firewall.hosts.has_key(self.client):
				raise "Rule refers to unknown host as client: '%s' at %s" \
					% (self.client, self.loginfo)
		# for services not yet defined, try to autocreate them
		if self.service != "" and self.service not in Firewall.services:
			try:
				s = Service(name=self.service,sports="",dports=self.service,
					include=None, loginfo=self.loginfo)
				Firewall.services[self.service] = s
			except PortInvalidSpec:
				raise "Rule refers to unknown service: '%s' at %s" \
					% (self.service, self.loginfo)

