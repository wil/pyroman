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
from port import Port
from chain import Chain

class Nat:
	"""
	Represents a Network Address Translation rule.
	"""
	def __init__(self, client, server, ip, port, dport, dir, loginfo):
		"""
		Create a new NAT rule

		client -- clients allowed to access this NAT rule
		server -- host nick the NAT is applied to
		ip -- IP that is used in NAT
		port -- Ports that are used in NAT
		dport -- Destination port for single port redirections
		dir -- incoming, outgoing or bidirecitonal NAT

		Note that the NAT is always applied to the "server" host, the UI
		accessible function is responsible to eventually exchange client
		and server for "outgoing" NATs (where the naming of client, server
		makes more sense the other way, think of workstations accessing
		web server via a NAT)
		"""
		if server == "":
			raise "Nat lacking a server host (client: %s, server: %s, ip: %s) at %s" % (client, server, ip, loginfo)
		if ip == "":
			raise "Nat lacking IP address: (client: %s, server: %s) at %s" % (client, server, loginfo)
		if dir not in ["in", "out", "both"]:
			raise "Nat with invalid direction: (client: %s, server: %s, ip: %s, dir: %s) at %s" % (client, server, ip, dir, loginfo)
		if not Util.verify_ip(ip,nonet=True):
			raise "Nat with invalid IP address: (client: %s, server: %s, ip: %s) at %s" % (client, server, ip, loginfo)
		if port:
			try:
				self.port = Port(port)
			except PortInvalidSpec:
				raise "Nat port specification invalid: (client: %s, server: %s, ip: %s, port: %s) at %s " % (client, server, ip, port, loginfo)
		else:
			self.port = None
		if dport:
			try:
				self.dport = Port(dport)
			except PortInvalidSpec:
				raise "Nat dport specification invalid: (client: %s, server: %s, ip: %s, port: %s, dport: %s) at %s " % (client, server, ip, port, dport, loginfo)
		else:
			self.dport = None
		if self.dport and not (self.port.proto == self.dport.proto):
			raise "Nat ports have different protocols: (client: %s, server: %s, ip: %s, port: %s, dport: %s) at %s" % (client, server, ip, port, dport, loginfo)
		if dport and not port:
			raise "Nat with destination port, but no source port: (client: %s, server: %s, ip: %s, dport: %s) at %s" % (client, server, ip, dport, loginfo)
		self.client = Util.splitter.split(client)
		self.server = Util.splitter.split(server)
		self.ip = ip
		# port, dport are set above
		self.dir = dir
		self.loginfo = loginfo

	def gen_snat(self, client, server):
		"""
		Internal helper function, with client, server objects
		"""
		iff = client.iface.get_filter("d")
		target = "SNAT --to-source %s" % self.ip
		# do we have a port restriction?
		pfilter = ""
		if self.port and self.dport:
			pfilter = self.dport.get_filter_proto() + " " + self.dport.get_filter_port("s")
			target = target + ":%s" % self.port.port
		elif self.port:
			pfilter = self.port.get_filter_proto() + " " + self.port.get_filter_port("s")

		c = firewall.chains["natPOST"]
		for sip in server.ip:
			filter = iff[0] + " -s %s" % sip
			c.append("%s %s -j %s" % (filter, pfilter, target), self.loginfo)
			#firewall.append_rule("POSTROUTING", target=target, filter=filter+" "+pfilter, table="nat", loginfo=self.loginfo)

	def gen_dnat(self, client, server):
		"""
		Internal helper function, with client, server objects
		"""
		iff = client.iface.get_filter("s")
		filter = iff[0] + " -d %s" % self.ip
		# do we have a port restriction?
		pfilter = ""
		if self.port:
			pfilter = self.port.get_filter_proto() + " " + self.port.get_filter_port("d")

		c = firewall.chains["natPRE"]
		for sip in server.ip:
			target = "DNAT --to-destination %s" % sip
			if self.dport:
				target = target + ":%s" % self.dport.port
			c.append("%s %s -j %s" % (filter, pfilter, target), self.loginfo)
			#firewall.append_rule(parent="PREROUTING", target=target, filter=filter+" "+pfilter, table="nat", loginfo=self.loginfo)

	def generate(self):
		for c in self.client:
			for s in self.server:
				client = firewall.hosts[c]
				server = firewall.hosts[s]
				# sanity checks, that should be moved to "verify"
				if not client or not server:
					raise "Client or server not found for NAT defined at %s" % self.loginfo
				if client.iface == server.iface:
					raise "client interface and server interface match (i.e. cannot NAT!) for NAT defined at %s" % self.loginfo

				if self.dir in ["in", "both"]:
					self.gen_dnat(client, server)
				if self.dir in ["out", "both"]:
					self.gen_snat(client, server)
