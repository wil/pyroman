"""
Pyroman uses some standard chains, set in its config.
These chains are used by the "allow()", "reject()" and "drop()" commands.

The (small) benefits of using this approach is that you can easily disable
the rules (by modifying 'drop' and 'reject') without reloading your firewall
and that you get complete traffic counters in these chains.

If you don't want to use them, you can just remove this file altogether.

The variables "Firewall.accept", "Firewall.drop" and "Firewall.reject" are
used here, so you can change them in one place only.
"""
# note that we're using the lowercase chain name
Firewall.accept = "accept"
add_chain(Firewall.accept)
iptables(Firewall.accept, "-j ACCEPT")

# this is a silent drop
Firewall.drop = "drop"
add_chain(Firewall.drop)
iptables(Firewall.drop, "-j DROP")

# .. these are clean "reject" rules (i.e. send 'connection refused' back)
Firewall.reject = "reject"
add_chain(Firewall.reject)
iptables(Firewall.reject, "-p tcp -j REJECT --reject-with tcp-reset")
iptables(Firewall.reject, "-j REJECT")
