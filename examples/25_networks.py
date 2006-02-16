"""
Now we define "host" that actually reflect complete networks. Many policies
will not make a different between the individual hosts in these networks.
"""
# First is the internal network, we're using a /24 network here only
# and it's connected to our "internal" interface
add_host(
	name="INT",
	ip="10.0.0.0/24",
	iface="int"
)
# Our DMZ network uses another /24 network
# Although I'd suggest using real IPs there and avoid NAT, I'll use
# a RFC-1918 addresses in this example.
add_host(
	name="DMZ",
	ip="10.0.1.0/24",
	iface="dmz"
)
# Any other host, connected to our "external" interface
add_host(
	name="ANY",
	ip="0.0.0.0/0",
	iface="ext"
)
