"""
This is a couple of rules to setup logging of rejected packets (if you want to)
"""
remove_cruft = True
logging_enabled = False

# remove cruft
if remove_cruft:
	# reject invalid connections, don't log them
	iptables("INPUT",   "-m state --state INVALID -j DROP")
	iptables("FORWARD", "-m state --state INVALID -j DROP")
	iptables("OUTPUT",  "-m state --state INVALID -j DROP")
# log unknown packets with a limit
if logging_enabled:
	iptables("INPUT",   "-j LOG -m limit --limit 1/sec --log-prefix \"I-unknown:\"")
	iptables("FORWARD", "-j LOG -m limit --limit 1/sec --log-prefix \"F-unknown:\"")
	iptables("OUTPUT",  "-j LOG -m limit --limit 1/sec --log-prefix \"O-unknown:\"")
