"""
Define the networks available here, or more precisely "hostgroups".
Many of your policy rules will probably target whole subnets.
"""
add_host(
	name="ANY",
	ip="0.0.0.0/0",
	iface="any"
)
