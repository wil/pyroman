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
import config
from pyroman import firewall

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
			raise "Chain name length too long, use shorter nicknames: %s" % chain

		return chain
	make_chain_name = staticmethod(make_chain_name)

	def get_chain(inface, outface, client, server, loginfo):
		"""
		Make a chain for the given hosts and add it to the interface chain
		"""
		chain = Chain.make_chain_name(inface, outface, client, server)
		if not chain in firewall.chains:
			firewall.rules.append( ("%s -N %s" % (config.iptables, chain), loginfo) )

			parent = "FORWARD"

			# if we are talking about localhost, things are different...
			if client and client.islocalhost():
				parent = "OUTPUT"
				if not outface:
					outface = inface
				inface = None
			if server and server.islocalhost():
				parent = "INPUT"
				if not inface:
					inface = outface
				outface = None

			# this is localhost talking to localhost...
			if server and server.islocalhost() and client and client.islocalhost():
				raise "Localhost talking to localhost?"

			crules = [""]
			srules = [""]
			ifrules = [""]
			ofrules = [""]
			if client:
				crules = client.get_filter("s")
			if server:
				srules = server.get_filter("d")
			if inface:
				ifrules = inface.get_filter("s")
			if outface:
				ofrules = outface.get_filter("d")

			for cr in crules:
				for sr in srules:
					for infi in ifrules:
						for outfi in ofrules:
							filter = "%s %s %s %s" % (infi, outfi, cr, sr)
							firewall.append_rule(parent, chain, filter, loginfo=loginfo)

			firewall.chains[chain]=True
		return chain
	get_chain = staticmethod(get_chain)

