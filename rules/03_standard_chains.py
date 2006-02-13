"""
Pyroman uses some standard chains, set in it's config. The defaults are
do_accept, do_drop, do_reject, and they correspond to the usual firewall
behaviour. If you want maximal performance, you'll want to change these
to ACCEPT and DROP directly.

The (small) benefits of using this approach is that you can easily disable
the rules (by modifying do_drop and do_reject) without reloading your firewall
and that you get complete traffic counters in these chains.
"""

append_rule_early("""
$ipt -N do_accept
$ipt -A do_accept -j ACCEPT
$ipt -N do_drop
$ipt -A do_drop -j DROP
$ipt -N do_reject
$ipt -A do_reject -p tcp -j REJECT --reject-with tcp-reset
$ipt -A do_reject -j REJECT --reject-with icmp-port-unreachable
""")
