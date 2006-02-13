"""
We don't want to have any restrictions on the loopback interface,
and want to have the allow rules early in the firewall rules
"""
iptables("INPUT", "-i lo -j ACCEPT")
iptables("OUTPUT", "-o lo -j ACCEPT")
