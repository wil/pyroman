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
import sys, socket, signal, re
from util import Util
from iptables import Iptables
#import iptables_parse
from exception import PyromanException
import subprocess

class Firewall:
	"""
	Main firewall class.
	Note that the current code is NOT designed to support multiple
	firewall objects, but only uses class variables.

	hostname -- automatically filled with the computers hostname
	timeout -- timeout for confirmation of the firewall by the user. 0 will disable auto-rollback
	vercmd -- command to do an external firewall verification
	accept -- target chain name for the accept() user command
	drop -- target chain name for the drop() user command
	reject -- target chain name for the reject() user command

	services -- hashmap of known services
	hosts -- hashmap of known hosts
	interfaces -- hashmap of known interfaces
	chains -- hashmap of known chains
	nats -- list of NAT rules
	rules -- list of firewall rules
	"""
	hostname = socket.gethostname()
	# Timeout when the firewall setup will be rolled back when
	# no OK is received.
	timeout = 0

	# Don't do external verification by default
	vercmd = None

	# Target names for the "accept", "drop" and "reject" commands
	accept = "ACCEPT"
	drop = "DROP"
	reject = "REJECT"

	input = "INPUT"
	output = "OUTPUT"
	forward = "FORWARD"

	services = {}
	hosts = {}
	interfaces = {}
	chains = {}
	nats = []
	rules = []

	# forwarding firewall. Default to yes
	forwarding = True

	# for testing kernel version
	kernelversioncmd = ["/bin/uname", "-r"]
	_kernelversion = None

	def __init__(self):
		"""
		Dummy initialization function, will raise PyromanException(an exception!)
		"""
		raise PyromanException("Instanciation not supported!")

	class Error(Exception):
		"""
		Basic Exception class
		"""
		pass

	def verify():
		"""
		Verify the data inserted into the firewall
		"""
		for s in Firewall.services.values():
			s.verify()
		for h in Firewall.hosts.values():
			h.verify()
		for i in Firewall.interfaces.values():
			i.verify()
		for r in Firewall.rules:
			r.verify()
	verify = staticmethod(verify)

	def prepare():
		"""
		Prepare for generation run
		"""
		for s in Firewall.services.values():
			s.prepare()
		for h in Firewall.hosts.values():
			h.prepare()
		for i in Firewall.interfaces.values():
			i.prepare()
		for r in Firewall.rules:
			r.prepare()
	prepare = staticmethod(prepare)

	def iptables_version(min=None, max=None):
		"""
		Return iptables version or test for a minimum and/or maximum version

		min -- minimal iptables version required
		max -- maximum iptables version required
		"""
		return Iptables.version(min=min, max=max)
	
	iptables_version = staticmethod(iptables_version)

	def generate():
		"""
		Generate the rules from the specifications given
		"""
		Firewall.prepare()
		for r in Firewall.rules:
			r.generate()
		for n in Firewall.nats:
			n.generate()
	generate = staticmethod(generate)

	def calciptableslines():
		"""
		Calculate the lines to be passed to iptables
		"""
		# prepare firewall rules
		l4, l6 = [], []
		# collect tables
		tables = []
		for c in Firewall.chains.values():
			if not c.table in tables:
				tables.append(c.table)
		# process tables
		for t in tables:
			# try to provide some useful help info, in case some error occurs
			l4.append( ["*%s" % t, "table select statement for table %s" % t] )
			l6.append( ["*%s" % t, "table select statement for table %s" % t] )
			# first create all chains
			for c in Firewall.chains.values():
				if c.table == t:
					l4.append( [c.get_init(), c.loginfo] )
					l6.append( [c.get_init(), c.loginfo] )
			# then write rules (which might -j to a table not yet created otherwise)
			for c in Firewall.chains.values():
				if c.table == t:
					for l in c.get_rules4():
						l4.append(l)
					for l in c.get_rules6():
						l6.append(l)
			# commit after each table, try to make a useful error message possible
			l4.append(["COMMIT", "commit statement for table %s" % t ])
			l6.append(["COMMIT", "commit statement for table %s" % t ])
		return l4, l6
	calciptableslines = staticmethod(calciptableslines)

	def rollback(savedlines):
		"""
		Rollback changes to the firewall, and report rollback success to the user

		savedlines -- saved firewall setting to be restored.
		"""
		# restore old iptables rules
		restored = Iptables.restore(savedlines)
		if restored:
			sys.stderr.write("*"*70+"\n")
			sys.stderr.write("  FIREWALL ROLLBACK FAILED.\n")
			sys.stderr.write("*"*70+"\n")
		else:
			sys.stderr.write("Firewall initialization failed. Rollback complete.\n")
	rollback = staticmethod(rollback)

	def print_rules(verbose):
		"""
		Print the calculated rules, as they would be passed to iptables.
		"""
		r4, r6 = Firewall.calciptableslines()
		print "#### IPv4 rules"
		for line in r4:
			if verbose:
				# print reasoning
				print "# %s" % line[1]
			print line[0]
		print "#### IPv6 rules"
		for line in r6:
			if verbose:
				# print reasoning
				print "# %s" % line[1]
			print line[0]
	print_rules = staticmethod(print_rules)

	def execute_rules(terse_mode=False):
		"""
		Execute the generated rules, rollback on error.
		If Firewall.timeout is set, give the user some time to accept the
		new configuration, otherwise roll back automatically.
		"""
		def user_confirm_timeout_handler(signum, frame):
			"""
			This handler is called when the user does not confirm
			firewall changes withing the given time limit.
			The firewall will then be rolled back.
			"""
			raise Firewall.Error("Success not confirmed by user")

		r4, r6 = Firewall.calciptableslines()

		# Save old firewall.
		if terse_mode:
			sys.stderr.write("backing up current... ")
		else:
			sys.stderr.write("Backing up current firewall...\n")
		savedlines = Iptables.save()

		# parse the firewall setup
		#try:
		#	parsed = iptables_parse.parse(savedlines)
		#except:
		#	pass

		# now try to execute the new rules
		successful = False
		try:
			if terse_mode:
				sys.stderr.write("activating new... ")
			successful = Iptables.commit(r4)
			if terse_mode:
				sys.stderr.write("success")
			else:
				sys.stderr.write("New firewall commited successfully.\n")
			if Firewall.vercmd:
				vcmd = subprocess.Popen(Firewall.vercmd, shell=True,
					stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				result = vcmd.communicate()
				if len(result[0]) > 0 or len(result[1]) > 0:
					if len(result[0]) > 0:
						sys.stderr.write("Verification command output:\n")
						sys.stderr.write(result[0])
					if len(result[1]) > 0:
						sys.stderr.write("Verification command error output:\n")
						sys.stderr.write(result[1])
				if vcmd.returncode != 0:
					raise Firewall.Error("External verification command failed.")
			if Firewall.timeout > 0:
				sys.stderr.write("To accept the new configuration, type 'OK' within %d seconds!\n" % Firewall.timeout)
				# setup timeout
				signal.signal(signal.SIGALRM, user_confirm_timeout_handler)
				signal.alarm(Firewall.timeout)
				# wait for user input
				input = sys.stdin.readline()
				# reset alarm handling
				signal.alarm(0)
				signal.signal(signal.SIGALRM, signal.SIG_DFL)

				if not re.search("^(OK|YES)", input, re.I):
					raise Firewall.Error("Success not confirmed by user")
		except Iptables.Error, e:
			if terse_mode:
				sys.stderr.write("error... restoring backup.\n")
			else:
				sys.stderr.write("*"*70+"\n")
				sys.stderr.write("An Iptables error occurred. Starting firewall restoration.\n")
			Firewall.rollback(savedlines)
			# show exception
			sys.stderr.write("%s\n" % e);
		except Firewall.Error, e:
			if terse_mode:
				sys.stderr.write("error. Restoring old firewall.\n")
			else:
				sys.stderr.write("*"*70+"\n")
				sys.stderr.write("A Firewall error occurred. Starting firewall restoration.\n")
			Firewall.rollback(savedlines)
			# show exception
			sys.stderr.write("%s\n" % e);
		except:
			if terse_mode:
				sys.stderr.write("error. Restoring old firewall.\n")
			else:
				sys.stderr.write("*"*70+"\n")
				sys.stderr.write("An unknown error occurred. Starting firewall restoration.\n")
			Firewall.rollback(savedlines)
			sys.stderr.write("\nHere is the exception triggered during execution:\n")
			raise
	execute_rules = staticmethod(execute_rules)
	
	def kernel_version(min=None, max=None):
		"""
		Return kernel version or test for a minimum and/or maximum version

		min -- minimal kernel version required
		max -- maximum kernel version required
		"""
		if not Firewall._kernelversion:
			# query iptables version
			kvcmd = subprocess.Popen(Firewall.kernelversioncmd,
				stdout=subprocess.PIPE)
			result = kvcmd.communicate()[0]
			Firewall._kernelversion = result.strip()
			# still no version number? - raise PyromanException(an exception)
			if not Firewall._kernelversion:
				raise Error("Couldn't get kernel version!")
		if not min and not max:
			return Firewall._kernelversion
		if min:
			if Util.compare_versions(Firewall._kernelversion, min) < 0:
				return False
		if max:
			if Util.compare_versions(Firewall._kernelversion, max) > 0:
				return False
		return True
	kernel_version = staticmethod(kernel_version)
