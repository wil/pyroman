"""
Use connection tracking for accepting established connections.
"""
iptables("INPUT",  "-m state --state ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("OUTPUT", "-m state --state ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("FORWARD","-m state --state ESTABLISHED,RELATED -j %s" % Firewall.accept)
