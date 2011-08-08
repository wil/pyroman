"""
We don't want to have any restrictions on the loopback interface,
and want to have the allow rules early in the firewall rules
"""
ipXtables("INPUT", "-i lo -j ACCEPT")
ipXtables("OUTPUT", "-o lo -j ACCEPT")
