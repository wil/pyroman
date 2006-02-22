"""
This is our firewall host. Since we're going to use this policy on this host,
make sure the "hostname" propery is set to the value of the "hostname" command
so pyroman will detect that this is the local host.

When pyroman detects a "localhost", meaning hostname==Firewall.hostname, it
will put these rules into the "INPUT" and "OUTPUT" instead of the "FORWARD"
chains, so this is essential!

If you run Pyroman on only one host, it's safe to use Firewall.hostname here
just like we did with the broadcasts. If you want to use these rules on
multiple hosts (e.g. a failover firewall), you can setup different
policies this way but have the identical configuration files on both hosts!

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

# allow all outgoing connections by the firewall
allow(
	client="firewallI firewallD firewallE"
)
