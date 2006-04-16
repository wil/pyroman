"""
Broadcasts are a very special thing. We have to treat them like they
were addressed to localhost on any host. For this we use a tiny trick with
PyroMan - the Firewall.hostname variable.

Also note that there are different kinds of broadcasts. A client searching
for a DHCP server will (have to) use the address "255.255.255.255", while
a client with a real IP will use the broadcast suiteable for his network
and netmask.

DHCP clients will also use the source IP 0.0.0.0, we should treat that
properly. Maybe it would have been easier to just handle this using raw
iptables commands than the PyroMan framework...

We define a different pseudo host "broadcast" for each network, since we
have different broadcast addresses on each, and don't want to allow
neither incorrect broadcasts, nor have the same broadcast services on
each of the interfaces. A simpler setup would use only one broadcast vhost,
and assign all broadcast adresses to it.
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

# Allow DHCP requests on internal interface (no valid client IP availble)
allow(server="broadcastI", service="dhcp")
# allow heartbeat (high-availability/failover) on all interfaces
# this is crypted, so no need to do any client restirctions
allow(server="broadcastI broadcastD broadcastE", service="heartb")
