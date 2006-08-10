"""
Use connection tracking for accepting established connections.

Allowing already established connections as well as related connections
(e.g. data connections for FTP control channels) is usually safe. This will
match most of the traffic, so the other rules only apply to not yet established
connections.
"""
iptables("INPUT",  "-m state --state ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("INPUT",  "-m state --state INVALID -j %s" % Firewall.drop)
iptables("OUTPUT", "-m state --state ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("OUTPUT",  "-m state --state INVALID -j %s" % Firewall.drop)
iptables("FORWARD","-m state --state ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("FORWARD",  "-m state --state INVALID -j %s" % Firewall.drop)
