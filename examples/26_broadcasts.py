"""
Broadcasts are a very special thing. We have to treat them like they
were addressed to localhost on any host. For this we need to do some minor
hacks with PyroMan, see below.

Also note that there are different kinds of broadcasts. A client searching
for a DHCP server will (have to) use the address "255.255.255.255", while
a client with a real IP will use the broadcast suiteable for his network
and netmask.

DHCP clients will also use the source IP 0.0.0.0, we should treat that
properly. Maybe it would have been easier to just handle this using raw
iptables commands than the PyroMan framework...
"""
# internal broadcasts
add_host(
	name="broadcastI",
	hostname=Firewall.hostname, # always on localhost!
	ip="255.255.255.255 10.0.0.255",
	iface="int"
)
# broadcasts in DMZ network
add_host(
	name="broadcastD",
	hostname=Firewall.hostname, # always on localhost!
	ip="255.255.255.255 10.0.1.255",
	iface="dmz"
)
# broadcasts in external network
add_host(
	name="broadcastE",
	hostname=Firewall.hostname, # always on localhost!
	ip="255.255.255.255 12.34.56.255",
	iface="ext"
)

# We don't specify client here - heartbeat is crypted and stateless,
# and DHCP doesn't have a valid (routed) source IP anyway.
allow(server="broadcastI", service="heartb dhcp")
allow(server="broadcastD", service="heartb")
allow(server="broadcastE", service="heartb")
