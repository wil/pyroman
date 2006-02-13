"""
The workstation network are several hosts which are not to be accessible
from the outside, but which may access just about anything - although they
are mainly used for email and surfing anyway.

The remaining hosts in the DMZ network are treated similarly.

We don't define a host here - we use the earlier defined network.
Other "special" hosts in the network will be treated separately by earlier
rules, this is a mere "default" rule.
"""
# reject windows broadcasts and filesharing
reject(
	client = "INT DMZ",
	server = "ANY",
	service = "fshare win"
)

# allow any other surfing
allow(
	client = "INT DMZ",
	server = "ANY"
)

# we also need to NAT the hosts in these network
# this is an outgoing NAT (which is treated somewhat special, by
# applying the IP to the client instead of using it as filter
# but this syntax seemed more intuitive...

# if your DMZ uses real IPs, you can remove it from the clients
add_nat(
	client="INT DMZ",
	server="ANY",
	ip="12.34.56.78",
	dir="out"
)
