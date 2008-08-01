#Copyright (c) 2007 Erich Schubert erich@debian.org

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
import sys, re
import subprocess
from util import Util
from exception import PyromanException

class Iptables:
	"""
	Interface to controlling iptables
	"""
	# iptables commands to use
	iptablessave = [ "/sbin/iptables-save", "-c" ]
	iptablesrestore = [ "/sbin/iptables-restore", "-c" ]
	iptablesset = [ "/sbin/iptables-restore" ]
	iptablesversion = [ "/sbin/iptables", "--version" ]

	# match for debugging errors
	match_errorline = re.compile(r"^Error occurred at line: ([0-9]+)$")
	match_errormsg  = re.compile(r"^iptables-restore(?: v[0-9.]+)?: (?:iptables-restore: )?(.+)$")
	match_hidemsg   = re.compile(r"^Try `iptables-restore -h' or 'iptables-restore --help' for more information.$")
	match_version   = re.compile(r"^iptables v([0-9]+\.[0-9.]+)$", re.M)

	# version number cache
	_version = None

	# Handled error class
	class Error(Exception):
		"""
		Basic exception class
		"""
		pass

	def version(min=None, max=None):
		"""
		Return iptables version or test for a minimum and/or maximum version

		min -- minimal iptables version required
		max -- maximum iptables version required
		"""
		if not Iptables._version:
			# query iptables version
			ivcmd = subprocess.Popen(Iptables.iptablesversion,
				stdout=subprocess.PIPE)
			ivstr = ivcmd.communicate()[0]
			m = Iptables.match_version.match(ivstr)
			if m and m.group(1):
				Iptables._version = m.group(1)
			# still no version number? - raise PyromanException(an exception)
			if not Iptables._version:
				raise Error("Couldn't get iptables version!")
		if not min and not max:
			return Iptables._version
		if min:
			if Util.compare_versions(Iptables._version, min) < 0: return False
		if max:
			if Util.compare_versions(Iptables._version, max) > 0: return False
		return True

	version = staticmethod(version)

	def save():
		"""
		Dump current iptables ruleset into an array of strings
		"""
		# save old iptables status
		scmd = subprocess.Popen(Iptables.iptablessave,
			stdout=subprocess.PIPE, stderr=sys.stderr)
		return scmd.communicate()[0].split("\n")
	save = staticmethod(save)

	def restore(savedlines):
		"""
		Restore iptables rules from a list of strings
		(generated by iptables_save)
		"""
		# restore old iptables rules
		rcmd = subprocess.Popen(Iptables.iptablesrestore,
			stdin=subprocess.PIPE, stdout=sys.stderr, stderr=sys.stderr)
		for line in savedlines:
			rcmd.stdin.write(line)
		rcmd.communicate()
		return rcmd.returncode
	restore = staticmethod(restore)

	def commit(lines):
		"""
		Commit iptables rules from a list of (annotated!) commands
		"""
		# TODO: verify that the lines don't contain linewraps
		# and have logging info!
		scmd = subprocess.Popen(Iptables.iptablesset,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		for line in lines:
			scmd.stdin.write(line[0])
			scmd.stdin.write("\n")
		scmd.stdin.close()
		# output any error
		errormsg = [ None, None ]
		for line in scmd.stdout.readlines():
			# skip empty lines
			if line=="\n":
				continue
			# try to grab the error message with line number
			if not errormsg[1]:
				m = Iptables.match_errorline.match(line)
				if m:
					errormsg[1] = lines[int(m.group(1))-1][1]
					continue
			# try to grab a detailed error description
			if not errormsg[0]:
				m = Iptables.match_errormsg.match(line)
				if m:
					errormsg[0] = m.group(1)
					continue
			# ignore the default "info" message
			m = Iptables.match_hidemsg.match(line)
			if m:
				continue
			# print remaining lines
			sys.stderr.write(line)
		success = (scmd.wait() == 0)
		if not success:
			if errormsg:
				raise Iptables.Error("Firewall commit failed: %s, caused by %s" % (errormsg[0], errormsg[1]))
			else:
				raise Iptables.Error("Firewall commit failed due to unknown error.")
		return success
	commit = staticmethod(commit)
