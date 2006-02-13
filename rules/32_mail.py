"""
This is an example configuration for a mail server.
"""
# a really simple host definition
add_host(
	name="mail",
	ip="10.100.1.1",
	iface="dmz"
)
# and offering a whole set of services with just one statement.
allow(
	client="ANY DMZ INT",
	server="mail",
	service="mail www ssh ping"
)

# But we need to setup a NAT for this host
# This is a bidirection nat, i.e. this host will use the .79
# IP for outgoing connections, too.
add_nat(
	client="ANY INT",
	server="mail",
	ip="12.34.56.79",
	dir="both"
)
