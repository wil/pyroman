"""
Use connection tracking for accepting established connections.
"""
append_rule_early("""
# Accept established (and related) connections
$ipt -A INPUT -m state --state ESTABLISHED,RELATED -j do_accept
$ipt -A OUTPUT -m state --state ESTABLISHED,RELATED -j do_accept
$ipt -A FORWARD -m state --state ESTABLISHED,RELATED -j do_accept
""")
