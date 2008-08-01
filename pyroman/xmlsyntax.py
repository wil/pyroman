#Copyright (c) 2008 Erich Schubert erich@debian.org

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
from util import Util
from exception import PyromanException
from xml.dom import minidom
import host, service, interface, nat, rule, chain

def parseXML(filename):
	"""
	Parse an XML file into pyroman statements.

	filename -- filename to be parsed.
	"""
	tree = minidom.parse(filename)
	docroot = tree.documentElement
	assert(docroot.nodeName == "pyroman")

	for node in docroot.childNodes:
		if node.nodeType == node.ELEMENT_NODE:
			_processNode(node, filename)

def _processNode(node, filename=None):
	"""
	Process a single node from the document tree
	"""
	if node.nodeName == "iptables":
		_processIptablesNode(node, filename)
	elif node.nodeName == "host":
		_processHostNode(node, filename)
	elif node.nodeName == "interface":
		_processInterfaceNode(node, filename)
	elif node.nodeName == "service":
		_processServiceNode(node, filename)
	elif node.nodeName == "chain":
		_processChainNode(node, filename)
	elif node.nodeName == "nat":
		_processNatNode(node, filename)
	elif node.nodeName == "allow" \
	or node.nodeName == "drop" \
	or node.nodeName == "reject" \
	or node.nodeName == "rule":
		_processRuleNode(node, filename)

def _processIptablesNode(node, filename=None):
	"""
	Process a node equivalent to an iptables() command
	"""
	chain = None
	filter = None
	if node.hasAttribute("chain"):
		chain = node.getAttribute("chain")
	if node.hasAttribute("filter"):
		filter = node.getAttribute("filter")
		filter = filter.replace("*accept*", Firewall.accept)
		filter = filter.replace("*drop*", Firewall.drop)
		filter = filter.replace("*reject*", Firewall.reject)
	if chain == "*accept*":
		chain = Firewall.accept
	elif chain == "*drop*":
		chain = Firewall.drop
	elif chain == "*reject*":
		chain = Firewall.reject
	if not Firewall.chains.has_key(chain):
		raise PyromanException("Firewall chain %s not defined at %s" % (chain, filename))
	Firewall.chains[chain].append(filter, filename)

def _processChainNode(node, filename=None):
	"""
	Process a node equivalent to an add_chain() command
	"""
	name = None
	default = "-"
	table = "filter"
	id = None
	if node.hasAttribute("name"):
		name = node.getAttribute("name")
	if name == "*accept*":
		name = Firewall.accept
	elif name == "*drop*":
		name = Firewall.drop
	elif name == "*reject*":
		name = Firewall.reject
	if node.hasAttribute("default"):
		default = node.getAttribute("default")
	if node.hasAttribute("table"):
		table = node.getAttribute("table")
	if node.hasAttribute("id"):
		id = node.getAttribute("id")
	if not id: id = name
	if Firewall.chains.has_key(id):
		raise PyromanException("Firewall chain %s defined multiple times at %s" % (name, filename))
	Firewall.chains[id] = chain.Chain(name, filename, default=default, table=table)

def _processServiceNode(node, filename=None):
	"""
	Process a node equivalent to an add_service() command
	"""
	dict = {}
	if node.hasAttribute("name"):
		dict["name"] = node.getAttribute("name")
	if node.hasAttribute("sports"):
		dict["sports"] = node.getAttribute("sports")
	if node.hasAttribute("dports"):
		dict["dports"] = node.getAttribute("dports")
	if node.hasAttribute("include"):
		dict["include"] = node.getAttribute("include")
	if filename:
		dict["loginfo"] = filename
	service.Service(**dict)

def _processInterfaceNode(node, filename=None):
	"""
	Process a node equivalent to an add_interface() command
	"""
	dict = {}
	if node.hasAttribute("name"):
		dict["name"] = node.getAttribute("name")
	if node.hasAttribute("iface"):
		dict["iface"] = node.getAttribute("iface")
	if filename:
		dict["loginfo"] = filename
	interface.Interface(**dict)

def _processHostNode(node, filename=None):
	"""
	Process a node equivalent to an add_host() command
	"""
	dict = {}
	if node.hasAttribute("name"):
		dict["name"] = node.getAttribute("name")
	if node.hasAttribute("ip"):
		dict["ip"] = node.getAttribute("ip")
	if node.hasAttribute("iface"):
		dict["iface"] = node.getAttribute("iface")
	if node.hasAttribute("hostname"):
		dict["hostname"] = node.getAttribute("hostname")
		if dict["hostname"] == "*localhost*":
			dict["hostname"] = Firewall.hostname
	if filename:
		dict["loginfo"] = filename
	host.Host(**dict)

def _processRuleNode(node, filename=None):
	"""
	Process a node corresponding to an allow/drop/reject or add_rule rule
	"""
	target=None
	server=""
	client=""
	service=""
	if node.hasAttribute("server"):
		server = node.getAttribute("server")
	if node.hasAttribute("client"):
		client = node.getAttribute("client")
	if node.hasAttribute("service"):
		service = node.getAttribute("service")
	if node.hasAttribute("target"):
		target = node.getAttribute("target")
	elif node.nodeName == "allow":
		target = "allow"
	elif node.nodeName == "drop":
		target = "drop"
	elif node.nodeName == "reject":
		target = "reject"

	if server=="" and client=="" and service=="":
		raise PyromanException("rule/allow/drop/reject node without any of server, client or service specified.")
	if not target:
		raise PyromanException("rule node without target!")

	for srv in Util.splitter.split(server):
		for cli in Util.splitter.split(client):
			for svc in Util.splitter.split(service):
				Firewall.rules.append(rule.Rule(target,srv,cli,svc,filename))

def _processNatNode(node, filename=None):
	"""
	Process a node corresponding to an add_nat statement
	"""
	client=""
	server=None
	ip=None
	port=None
	dport=None
	dir="in"
	if node.hasAttribute("client"):
		client = node.getAttribute("client")
	if node.hasAttribute("server"):
		server = node.getAttribute("server")
	if node.hasAttribute("ip"):
		ip = node.getAttribute("ip")
	if node.hasAttribute("port"):
		port = node.getAttribute("port")
	if node.hasAttribute("dport"):
		dport = node.getAttribute("dport")
	if node.hasAttribute("dir"):
		dir = node.getAttribute("dir")

	if not server or not ip:
		raise PyromanException("Server not specified for NAT at %s" % filename)

	if (dir == "out"):
		(client, server) = (server, client)
	Firewall.nats.append(nat.Nat(client, server, ip, port, dport, dir, filename))
