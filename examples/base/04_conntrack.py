"""
Use connection tracking for accepting established connections.

Allowing already established connections as well as related connections
(e.g. data connections for FTP control channels) is usually safe. This will
match most of the traffic, so the other rules only apply to NEW connections.

To stay true to the deny-everything-except-if-explicitly-allowed, rules for
NEW connections go into separate chains: input, output, and forward.
"""
add_chain('input')
iptables("INPUT", "-m conntrack --ctstate ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("INPUT", "-m conntrack --ctstate INVALID -j %s" % Firewall.drop)
iptables("INPUT", "-m conntrack --ctstate NEW -j input")

add_chain('output')
iptables("OUTPUT", "-m conntrack --ctstate ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("OUTPUT", "-m conntrack --ctstate INVALID -j %s" % Firewall.drop)
iptables("OUTPUT", "-m conntrack --ctstate NEW -j output")

add_chain('forward')
iptables("FORWARD", "-m conntrack --ctstate ESTABLISHED,RELATED -j %s" % Firewall.accept)
iptables("FORWARD", "-m conntrack --ctstate INVALID -j %s" % Firewall.drop)
iptables("FORWARD", "-m conntrack --ctstate NEW -j forward")
