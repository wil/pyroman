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
from chain import Chain
import config
import port, service, interface, host, nat, rule

def add_service(name, sports="", dports="", include=None):
	"""
	Add a new named service to the list of services

	name -- name of the new service
	sports -- source port specification like "www/tcp 53/udp"
	dports -- destination port specification
	include -- services to be included / aliased

	Note that services can be autocreated when names such as "www/tcp" or
	"53/udp" are used, so you mainly use this to group services or make easier
	aliases (e.g. "www" = "http/tcp https/tcp")
	"""
	loginfo = Util.get_callee(3)
	service.Service(name, sports, dports, include, loginfo)

def add_interface(name, iface):
	"""
	Create a new named interface

	name -- name for this interface (-group)
	iface -- kernel interfaces in this group, e.g. "eth0 eth1"
	"""
	loginfo = Util.get_callee(3)
	interface.Interface(name, iface, loginfo)

def add_host(name, ip, iface, hostname=None):
	"""
	Create a new host object.

	name -- Nickname for the host
	ip -- IP specification for host or subnet (e.g. "127.0.0.1 10.0.0.0/24")
	iface -- Interface nickname this is connected to (only one!)
	hostname -- Real hostname, as returned by "hostname". Used for
	            "localhost" detection only (i.e. use INPUT and OUTPUT, not
	            FORWARD chains), so only needed for these hosts. Defaults to
	            the nickname, which will usually be fine. You can use
	            hostname = Firewall.hostname to make e.g. a broadcast "host"
	            always "local".
	"""
	loginfo = Util.get_callee(3)
	if not hostname:
		hostname = name
	host.Host(name, ip, iface, hostname, loginfo)

def add_nat(client="", server=None, ip=None, port=None, dport=None, dir="in"):
	"""
	Create a new NAT rule

	client -- clients that may use this NAT
	server -- server to be accessed via this NAT
	ip -- IP that the NAT redirects/uses
	port -- Ports that are redirected by the NAT
	dport -- Destination port for the NAT
	dir -- set to "in", "out" or "both" for directions, default is "in"
	       beware that "out" inverts client, server, to make more sense
	       for hosts that aren't reachable from outside (i.e. NAT is
	       applied to the client, not to the server, whereas in "in" and
	       "both", it is always applied to the server)
	"""
	loginfo = Util.get_callee(3)
	if not server or not ip:
		raise "Server not specified for NAT (server: %s, ip: %s) at %s" % (server, ip, loginfo)
	# special case: "out" NAT type
	if dir=="out":
		(client, server) = (server, client)
	firewall.nats.append(nat.Nat(client, server, ip, port, dport, dir, loginfo))

def add_rule(target, server="", client="", service=""):
	"""
	Add an arbitrary rule to the list of rules.
	Allow, reject, drop are special cases of this.

	target -- target for the rule
	server -- server host nickname
	client -- client host nickname
	service -- service this rule applies to
	"""

	loginfo = Util.get_callee(4)
	if server == "" and client == "" and service == "":
		raise "allow() called without parameters at %s" % loginfo
	for srv in Util.splitter.split(server):
		for cli in Util.splitter.split(client):
			for svc in Util.splitter.split(service):
				firewall.rules_todo.append(rule.Rule(target,srv,cli,svc,loginfo))
	
def add_chain(name, default="-", table="filter", id=None):
	"""
	Create a new firewall chain.

	name -- name of the chain in iptables
	id -- internal ID for the chain, defaults to name
	default -- default target, use for built-in chains
	table -- table this chain resides in, defaults to "filter"
	"""
	if not id:
		id = name
	assert(not firewall.chains.has_key(id))
	firewall.chains[id] = Chain(name, default=default, table=table)

def allow(server="", client="", service=""):
	"""
	Add an 'allow' rule to the list of rules.
	This calls add_rule(config.accept, ...)

	server -- server host nickname
	client -- client host nickname
	service -- service this rule applies to
	"""
	add_rule(config.accept, server, client, service)
	
def reject(server="", client="", service=""):
	"""
	Add a 'reject' rule to the list of rules
	This calls add_rule(config.reject, ...)

	server -- server host nickname
	client -- client host nickname
	service -- service this rule applies to
	"""
	add_rule(config.reject, server, client, service)
	
def drop(server="", client="", service=""):
	"""
	Add a 'drop' rule to the list of rules
	This calls add_rule(config.drop, ...)

	server -- server host nickname
	client -- client host nickname
	service -- service this rule applies to
	"""
	add_rule(config.drop, server, client, service)

def iptables(chain, filter):
	assert(firewall.chains.has_key(chain))
	loginfo = Util.get_callee(3)
	firewall.chains[chain].append(filter, loginfo)

def iptables_end(chain, filter):
	assert(firewall.chains.has_key(chain))
	loginfo = Util.get_callee(3)
	firewall.chains[chain].append_end(filter, loginfo)
