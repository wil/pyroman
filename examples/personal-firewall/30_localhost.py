"""
Simple definition for localhost.

The magic thing is that hostname is Firewall.hostname, so the rules are used
in the INPUT and OUTPUT chains instead of FORWARD.
"""
add_host(
	name="localhost",
	hostname=Firewall.hostname,
	ip="0.0.0.0/0",
	iface="any"
)
# if you want a restriction on outgoing connections, add that here.
allow(
	client="localhost",
	server="ANY"
)
# only allow certain incoming connections:
allow(
	client="ANY",
	server="localhost",
	service="ssh mdns www ping"
)
# if you want to protect some 'unprivileged ports', add that here
# reject(
# 	client="ANY",
# 	server="localhost"
# 	service="8080/tcp"
# )

# open unprivileged ports by default. Remove if you don't want that.
allow(
	client="ANY",
	server="localhost",
	service="unprivileged"
)
