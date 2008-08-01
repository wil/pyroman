"""
Pyroman uses some standard chains, set in its config.
These chains are used by the "allow()", "reject()" and "drop()" commands.

If you want maximal performance, you'll want to change these to ACCEPT and DROP
directly by setting 'Firewall.accept = "ACCEPT"' and removing the lines below.

The (small) benefits of using this approach is that you can easily disable
the rules (by modifying 'drop' and 'reject') without reloading your firewall
and that you get complete traffic counters in these chains.

The variables "Firewall.accept", "Firewall.drop" and "Firewall.reject" are
used here, so you can change them in one place only.
"""
add_chain(Firewall.accept)
iptables(Firewall.accept, "-j ACCEPT")

# this is a silent drop
add_chain(Firewall.drop)
iptables(Firewall.drop, "-j DROP")

# .. these are clean "reject" rules (i.e. send 'connection refused' back)
add_chain(Firewall.reject)
iptables(Firewall.reject, "-p tcp -j REJECT --reject-with tcp-reset")
iptables(Firewall.reject, "-j REJECT")
