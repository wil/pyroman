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
import re, socket, inspect, sys
import config
from util import Util
from popen2 import popen3, Popen4
from select import select

class Firewall:
	hostname = socket.gethostname()

	def __init__(self):
		"""
		Create a firewall object. Note that the current code is NOT designed
		to support multiple firewall objects, but refers to the one named
		"firewall" in this file.
		"""
		self.services = {}
		self.hosts = {}
		self.interfaces = {}
		self.nats = []
		self.rules_todo = []
		self.chains = {}

	def append(self, list, cmd, loginfo=None):
		"""
		Append a shell command to one of the lists
		"""
		if not loginfo:
			loginfo = self.get_callee(4)
		cmd = cmd.replace("$ipt",config.iptables).replace("$ipr", config.iproute)
		lines = cmd.splitlines()
		for i in range(0,len(lines)):
			if not Util.ignoreline.match(lines[i]):
				list.append( (lines[i], "%s+%d" % (loginfo, i) ) )

	def append_rule(self, parent, target, filter, table="", loginfo=None):
		"""
		Output an iptables rule with the given parameters.
		The table parameter is optional, just as with iptables.
		"""
		# handle optional table parameter nicely
		if table != "":
			table = " -t " + table
		cmd = "%s%s -A %s %s -j %s" % (config.iptables, table, parent, filter, target )
		self.rules.append( (cmd, loginfo) )

	def verify(self):
		"""
		Verify the data inserted into the firewall
		"""
		for s in self.services.values():
			s.verify()
		for h in self.hosts.values():
			h.verify()
		for i in self.interfaces.values():
			i.verify()
		for r in self.rules_todo:
			r.verify()

	def prepare(self):
		"""
		Prepare for generation run
		"""
		for s in self.services.values():
			s.prepare()
		for h in self.hosts.values():
			h.prepare()
		for i in self.interfaces.values():
			i.prepare()
		for r in self.rules_todo:
			r.prepare()

	def generate(self):
		"""
		Generate the rules from the specifications given
		"""
		self.prepare()
		for r in self.rules_todo:
			r.generate()
		for n in self.nats:
			n.generate()

	def print_rules(self):
		"""
		(Unused, unmaintained code)
		Print the specifications as a shell script, including echo statements
		to explain the lines' origin. Useful for debugging.
		"""
		# collect tables
		tables = []
		for c in self.chains.values():
			if not c.table in tables:
				tables.append(c.table)
		# process tables
		for t in tables:
			print "*%s" % t
			# first create all tables
			for c in self.chains.values():
				if c.table == t:
					c.dump_init()
			# then write rules (which might -j to a table not yet created otherwise)
			for c in self.chains.values():
				if c.table == t:
					c.dump_rules()
			# commit after each table
			print "COMMIT"

	def iptables_save(self):
		"""
		Save current iptables ruleset to a list of lines
		"""
		# save old iptables status
		sr, sw, se = popen3(config.iptablessave)
		sw.close()
		savedlines = sr.readlines()
		sr.close()
		for line in se.readlines():
			sys.stderr.write(line)
		se.close()
		return savedlines

	def iptables_restore(self, savedlines):
		"""
		Restore iptables rules from a list of lines
		(generated by iptables_save)
		"""
		# restore old iptables rules
		ipr = Popen4(config.iptablesrestore)
		rr, rw = ipr.fromchild, ipr.tochild
		for line in savedlines:
			rw.write(line)
		rw.close()
		# output any error
		for line in rr.readlines():
			sys.stderr.write(line)
		rr.close()
		return (ipr.wait() == 0)

	def execute_rules(self):
		"""
		Execute the generated rules
		"""
		sys.stderr.write("Saving old firewall...\n")
		savedlines = self.iptables_save()

		sys.stderr.write("*"*70+"\n")
		sys.stderr.write("Beginning firewall initialization...\n")
		# now try to execute the new rules
		successful = False
		try:
			ipr = Popen4(config.iptablesset)
			rr, rw = ipr.fromchild, ipr.tochild

			# collect tables
			tables = []
			for c in self.chains.values():
				if not c.table in tables:
					tables.append(c.table)
			# process tables
			for t in tables:
				rw.write("*%s\n" % t)
				# first create all tables
				for c in self.chains.values():
					if c.table == t:
						rw.write(c.get_init())
				# then write rules (which might -j to a table not yet created otherwise)
				for c in self.chains.values():
					if c.table == t:
						for l in c.get_rules():
							rw.write(l)
				# commit after each table
				rw.write("COMMIT\n")
			rw.close()

			# output any error
			for line in rr.readlines():
				sys.stderr.write(line)

			if ipr.wait() != 0:
				successful = False
				raise "An error occurred during setting the new firewall"
			successful = True
		finally:
			if not successful:
				sys.stderr.write("*"*70+"\n")
				sys.stderr.write("An error occurred. Starting firewall restoration.\n")
				# restore old iptables rules
				restored = self.iptables_restore(savedlines)
				sys.stderr.write("*"*70+"\n")
				if restored:
					sys.stderr.write("  FIREWALL ROLLBACK FAILED.\n")
					sys.stderr.write("*"*70+"\n")
				else:
					sys.stderr.write("Firewall initialization failed. Rollback complete.\n")
					sys.stderr.write("Note that only iptable can be rolled back, not e.g. routing.\n")
				sys.stderr.write("\nHere is the exception triggered during execution:\n")

firewall = Firewall()
