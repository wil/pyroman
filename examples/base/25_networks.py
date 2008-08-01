"""
Define the networks available here, or more precisely "hostgroups".
Many of your policy rules will probably target whole subnets.
"""
# First is the internal network, we're using a /24 network here only
# and it's connected to our "internal" interface
#add_host(
#	name="INT",
#	ip="10.0.0.0/24",
#	iface="int"
#)
