"""
Pyroman uses some standard chains, set in it's config. The defaults are
do_accept, do_drop, do_reject, and they correspond to the usual firewall
behaviour. If you want maximal performance, you'll want to change these
to ACCEPT and DROP directly.

The (small) benefits of using this approach is that you can easily disable
the rules (by modifying do_drop and do_reject) without reloading your firewall
and that you get complete traffic counters in these chains.
"""
add_chain(Firewall.accept)
iptables(Firewall.accept, "-j ACCEPT")
add_chain(Firewall.drop)
iptables(Firewall.drop, "-j DROP")
add_chain(Firewall.reject)
iptables(Firewall.reject, "-p tcp -j REJECT --reject-with tcp-reset")
iptables(Firewall.reject, "-j REJECT --reject-with icmp-port-unreachable")
