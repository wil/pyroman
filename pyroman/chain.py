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
from exception import PyromanException

class Chain:
	"""
	Helper functions for chain management
	"""
	def make_chain_name(inface, outface, client, server):
		"""
		Generate chain name from interface and host names

		The maximum length for iptables is 32 chars, this will be
		checked and an error reported if the name becomes too long.
		"""
		if client and client.islocalhost():
			if not outface:
				outface = inface
			inface = None
		if server and server.islocalhost():
			if not inface:
				inface = outface
			outface = None

		# get ascii names
		ifname, ofname, cname, sname = ("","","","")
		if inface:
			ifname = inface.name
		if outface:
			ofname = outface.name
		if client:
			cname = client.name
		if server:
			sname = server.name

		chain = "%s_%s_%s_%s" % (ifname, ofname, cname, sname)
		if len(chain) >= 32:
			raise PyromanException("Chain name length too long, use shorter nicknames: %s" % chain)

		return chain
	make_chain_name = staticmethod(make_chain_name)

	def get_chain(inface, outface, client, server, loginfo):
		"""
		Make a chain for the given hosts and add it to the interface chain
		"""
		chain = Chain.make_chain_name(inface, outface, client, server)
		if not Firewall.chains.has_key(chain):
			c = Chain(chain, loginfo)

			parent = Firewall.forward

			# if we are talking about localhost, things are different...
			if client and client.islocalhost():
				parent = Firewall.output
				if not outface:
					outface = inface
				inface = None
			if server and server.islocalhost():
				parent = Firewall.input
				if not inface:
					inface = outface
				outface = None

			if not Firewall.chains.has_key(parent):
				raise PyromanException("Unknown chain specified: %s" % parent)
			p = Firewall.chains[parent]

			# this is localhost talking to localhost...
			if server and server.islocalhost() and client and client.islocalhost():
				raise PyromanException("Localhost talking to localhost?")

			crules4 = [""]
			crules6 = [""]
			srules4 = [""]
			srules6 = [""]
			ifrules = [""]
			ofrules = [""]
			if client:
				crules4 = client.get_filter4("s")
				crules6 = client.get_filter6("s")
			if server:
				srules4 = server.get_filter4("d")
				srules6 = server.get_filter6("d")
			if inface:
				ifrules = inface.get_filter("s")
			if outface:
				ofrules = outface.get_filter("d")

			for cr in crules4:
				for sr in srules4:
					for infi in ifrules:
						for outfi in ofrules:
							filter = "%s %s %s %s -j %s" % (infi, outfi, cr, sr, chain)
							p.append4(filter, loginfo)

			for cr in crules6:
				for sr in srules6:
					for infi in ifrules:
						for outfi in ofrules:
							filter = "%s %s %s %s -j %s" % (infi, outfi, cr, sr, chain)
							p.append6(filter, loginfo)

			Firewall.chains[chain]=c
			return c
		else:
			return Firewall.chains[chain]
	get_chain = staticmethod(get_chain)

	def __init__(self, name, loginfo, default="-", table="filter"):
		"""
		Create a new chain

		name -- Name for this chain
		loginfo -- Why the chain was created, for error reporting
		default -- default target for this chain (for INPUT, OUTPUT, FORWARD)
		table -- table this chain resides in
		"""
		self.name = name
		self.loginfo = loginfo
		self.table = table
		self.default = default
		self.rules4 = []
		self.rules6 = []
		self.rules4_end = []
		self.rules6_end = []
	
	def append4(self, statement, loginfo):
		"""
		Append a statement to a chain
		"""
		self.rules4.append([statement, loginfo])

	def append4_end(self, statement, loginfo):
		"""
		Append a statement to a chain
		"""
		self.rules4_end.append([statement, loginfo])

	def append6(self, statement, loginfo):
		"""
		Append a statement to a chain
		"""
		self.rules6.append([statement, loginfo])

	def append6_end(self, statement, loginfo):
		"""
		Append a statement to a chain
		"""
		self.rules6_end.append([statement, loginfo])

	def get_init(self):
		"""
		Get the chain initializer statement
		"""
		return ":%s %s" % (self.name, self.default)

	def get_rules4(self):
		"""
		Get the rules for IPv4
		"""
		lines = []
		for r in self.rules4:
			lines.append(["-A %s %s" % (self.name, r[0]), r[1]])
		for r in self.rules4_end:
			lines.append(["-A %s %s" % (self.name, r[0]), r[1]])
		return lines

	def get_rules6(self):
		"""
		Get the rules for IPv6
		"""
		lines = []
		for r in self.rules6:
			lines.append(["-A %s %s" % (self.name, r[0]), r[1]])
		for r in self.rules6_end:
			lines.append(["-A %s %s" % (self.name, r[0]), r[1]])
		return lines
