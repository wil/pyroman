"""
Use connection tracking for accepting established connections.

Allowing already established connections as well as related connections
(e.g. data connections for FTP control channels) is usually safe. This will
match most of the traffic, so the other rules only apply to NEW connections.

To stay true to the deny-everything-except-if-explicitly-allowed, rules for
NEW connections go into separate chains: input, output, and forward.
"""
Firewall.input = "input"
add_chain(Firewall.input)
# IPv6 only: drop RH0 type.
ip6tables("INPUT", "-m rt --rt-type 0 -j %s" % Firewall.drop)
# Both IPv4 and IPv6: allow established connections
ipXtables("INPUT", "-m conntrack --ctstate ESTABLISHED,RELATED -j %s" % Firewall.accept)
ipXtables("INPUT", "-m conntrack --ctstate INVALID -j %s" % Firewall.drop)
ipXtables("INPUT", "-m conntrack --ctstate NEW -j %s" % Firewall.input)

Firewall.output = "output"
add_chain(Firewall.output)
# IPv6 only: drop RH0 type.
ip6tables("OUTPUT", "-m rt --rt-type 0 -j %s" % Firewall.drop)
# Both IPv4 and IPv6: allow established connections
ipXtables("OUTPUT", "-m conntrack --ctstate ESTABLISHED,RELATED -j %s" % Firewall.accept)
ipXtables("OUTPUT", "-m conntrack --ctstate INVALID -j %s" % Firewall.drop)
ipXtables("OUTPUT", "-m conntrack --ctstate NEW -j %s" % Firewall.output)

Firewall.forward = "forward"
add_chain(Firewall.forward)
# IPv6 only: drop RH0 type.
ip6tables("FORWARD", "-m rt --rt-type 0 -j %s" % Firewall.drop)
# Both IPv4 and IPv6: allow established connections
ipXtables("FORWARD", "-m conntrack --ctstate ESTABLISHED,RELATED -j %s" % Firewall.accept)
ipXtables("FORWARD", "-m conntrack --ctstate INVALID -j %s" % Firewall.drop)
ipXtables("FORWARD", "-m conntrack --ctstate NEW -j %s" % Firewall.forward)
