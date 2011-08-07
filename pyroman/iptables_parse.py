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
import sys, re, math
from xml.dom.minidom import getDOMImplementation
from xml.dom import minidom

# data collection variables
tables = dict()

# status variables
curtable = None

# some regexpes
counter_re = re.compile(r"^\[(\d+):(\d+)\]$")
# we're not enforcing much right now
# note that we're assuming anything behind the -j statement belongs to the jump
fullline_re = re.compile(r"^(?:\[(\d+):(\d+)\] )?(?:-A ([^ ]+))(?: (.*))?(?: -j ([^ ]+)(?: (.+))?)$")
# for splitting options, this uses a zero-width-lookahead to check for a -
optsplit_re = re.compile(r" (?=-)")

# from 1.3.6. documentation
builtin_targets = set([
	'ACCEPT', 'DROP', 'RETURN', \
	'CLASSIFY', 'CLUSTERIP', 'CONNMARK', 'CONNSECMARK', \
	'DNAT', 'DSCP', 'ECN', 'IPV4OPTSSTRIP', 'LOG', 'MARK', 'MASQUERADE', \
	'MIRROR', 'NETMAP', 'NFQUEUE', 'NOTRACK', 'REDIRECT', 'REJECT', \
	'ROUTE', 'SAME', 'SECMARK', 'SET', 'SNAT', 'TARPIT', 'TCPMSS', 'TOS', \
	'TRACE', 'TTL', 'ULOG'])

class parsedtable:
	def __init__(self, name):
		self.name = name
		self.chains = dict()

	def addChain(self, chain):
		assert(not self.chains.has_key(chain.name))
		self.chains[chain.name] = chain

	def getChain(self, chainname):
		return self.chains[chainname]

	def __str__(self):
		return self.name

	def link(self):
		for c in self.chains.keys():
			self.chains[c].link()

class parsedchain:
	def __init__(self, name, table, default, packets=None, bytes=None):
		self.name = name
		self.table = table
		self.default = default
		self.dpackets = packets
		self.dbytes = bytes
		self.tpackets = None
		self.tbytes = None

		# filled during linking
		self.references = set()
		self.referenced_by = set()

		if self.default == '-':
			self.default = 'RETURN'

		if name in builtin_targets:
			print >>sys.stderr, "Warning: chainname %s matches potential built-in chain." % name

		self.rules = []

		# register in table
		table.addChain(self)

	def appendRule(self, rule):
		self.rules.append(rule)

	def __str__(self):
		return self.name

	def link(self):
		"""
		Do chain interlinking as objects
		"""
		try:
			self.default = self.table.getChain(self.default)
			self.default.addReferenceBy(self)
		except KeyError:
			if not self.default in builtin_targets:
				print >>sys.stderr, "Target %s not found, and not in list of known builtins." % self.default
			pass
		self.references.add(self.default)

		for rule in self.rules:
			self.references.add(rule.link())
			self.references.add(rule)

	def addReferenceBy(self, other):
		self.referenced_by.add(other)

	def getObjects(self):
		"""
		Return objects referenced in this chain
		"""
		return self.references

	def getPackets(self):
		if self.dpackets == None: return None
		if self.tpackets == None:
			self.calcPacketsBytes()
		return self.tpackets

	def getBytes(self):
		if self.dbytes == None: return None
		if self.tbytes == None:
			self.calcPacketsBytes()
		return self.tbytes

	def calcPacketsBytes(self):
		(tpackets, tbytes) = (self.dpackets, self.dbytes)
		for r in self.rules:
			tpackets += r.packets
			tbytes += r.bytes
		self.tpackets = tpackets
		self.tbytes = tbytes

class parsedrule:
	def __init__(self, chain, filter, target, targetopts, packets=None, bytes=None):
		self.chain = chain
		self.filter = filter
		self.target = target
		self.targetopts = targetopts
		self.packets = packets
		self.bytes = bytes

		# register in table
		chain.appendRule(self)

	def shortRule(self):
		filterstr = ""
		if self.filter:
			for f in self.filter:
				if f.startswith("-m "): continue
				filterstr += " " + f
		return filterstr[1:]
	
	def __str__(self):
		filterstr = ""
		if self.filter:
			filterstr = " ".join(self.filter)
		targetostr = ""
		if self.targetopts:
			targetostr = " ".join(self.targetopts)
		return "-A %s %s -j %s %s" % (self.target, filterstr, self.target, targetostr)
	
	def link(self):
		try:
			self.target = self.chain.table.getChain(self.target)
			self.target.addReferenceBy(self.chain)
		except KeyError:
			if not self.target in builtin_targets:
				print >>sys.stderr, "Target %s not found, and not in list of known builtins." % self.default
			pass
		return self.target

def parse(lines):
	for line in lines:
		line = line.strip()

		# skip comments
		if line[0] == '#': continue

		# beginning and end of a table
		if line[0] == '*':
			tablename = line[1:]
			assert(not tables.has_key(tablename))
			curtable = parsedtable(tablename)
			tables[tablename] = curtable
			continue
		if line == 'COMMIT':
			curtable = None
			continue

		# beginning of a new chain
		if line[0] == ':':
			assert(curtable)
			s = line[1:].split()
			assert( len(s) == 2 or len(s) == 3)
			(chainname, default) = s[0:2]
			(packets, bytes) = (None,None)
			if len(s) == 3:
				m = counter_re.match(s[2])
				assert(m)
				(packets, bytes) = (int(m.group(1)), int(m.group(2)))

			parsedchain(chainname, curtable, default, packets, bytes)
			continue
		
		# iptables statements
		m = fullline_re.match(line)
		if m:
			(packets, bytes) = (None, None)
			if m.group(1) and m.group(2):
				(packets, bytes) = (int(m.group(1)), int(m.group(2)))
			(chainname, filters) = (m.group(3),m.group(4))
			(target, targetopts) = (m.group(5),m.group(6))

			# do a best-guess split for the options
			if filters != None:
				filters = optsplit_re.split(filters)
			if targetopts != None:
				targetops = optsplit_re.split(targetopts)

			curchain = curtable.getChain(chainname)
			parsedrule(curchain, filters, target, targetopts, packets, bytes)
			continue

		print >>sys.stderr, "Line didn't parse: ", line

	# process chain interlinking
	for t in tables.keys():
		tables[t].link()
