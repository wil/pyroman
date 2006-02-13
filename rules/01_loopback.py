"""
We don't want to have any restrictions on the loopback interface,
and want to have the allow rules early in the firewall rules
"""
append_rule_early("""
$ipt -A INPUT -i lo -j ACCEPT
$ipt -A OUTPUT -o lo -j ACCEPT
""")
