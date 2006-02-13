"""
This is our firewall host. Since we're going to use this policy on this host,
make sure the "hostname" propery is set to the value of the "hostname" command
so pyroman will detect that this is the local host.

The firewall has three interfaces with different policies and several IPs.
There are different services running on the different interfaces.
Alltogether this is the most complex host in our configuration...

(Note that in my setup I have two copies of this host, which only differ
by the hostname and some of the IPs, and they do a failover)
"""
# on the internal interface
add_host(
	name="firewallI",
	hostname="firewall",
	ip="12.34.56.78 10.100.0.254 10.100.1.254",
	iface="int"
)
# on the DMZ interface
add_host(
	name="firewallD",
	hostname="firewall",
	ip="12.34.56.78 10.100.0.254 10.100.1.254",
	iface="dmz"
)
# in the external network
add_host(
	name="firewallE",
	hostname="firewall",
	ip="12.34.56.78",
	iface="ext"
)

# service definitions for the firewall
allow(
	client="INT",
	server="firewallI",
	service="http dns ssh ping heartb dhcp"
)
allow(
	client="DMZ",
	server="firewallD",
	service="http dns ssh ping heartb"
)
allow(
	client="ANY",
	server="firewallE",
	service="http dns ssh ping heartb openvpn"
)

# allow all outgoing connections
allow(
	client="firewallI firewallD firewallE"
)
