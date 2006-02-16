"""
A really simple webserver configuration.
These examples are just boring... ;-)

But without NAT they would be even more boring. ;-)
"""
# web server
add_host(
	name="web",
	ip="10.100.1.2",
	iface="dmz"
)
# offering, well, web service.
allow(
	client="ANY DMZ INT",
	server="web",
	service="www ssh ping"
)
# internal hosts may access FTP, too
allow(
	client="INT",
	server="web",
	service="ftp"
)
# setup NAT
add_nat(
	client="ANY INT",
	server="web",
	ip="12.34.56.80"
)
