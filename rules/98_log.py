append_rule_end("""
# silently drop routing announcements
$ipt -A INPUT -p udp --dport route -j DROP
# drop windows shares
$ipt -A INPUT -p tcp --dport 135:139 -j REJECT --reject-with tcp-reset
$ipt -A INPUT -p udp --dport 135:139 -j DROP
$ipt -A INPUT -p tcp --dport 445 -j REJECT --reject-with tcp-reset
$ipt -A INPUT -p udp --dport 445 -j DROP
# messenger spam
$ipt -A INPUT -p udp --dport 1026 -j DROP

$ipt -A INPUT -p tcp --dport  113 -j REJECT --reject-with tcp-reset
$ipt -A INPUT -p tcp --dport  161 -j REJECT --reject-with tcp-reset
$ipt -A INPUT -p tcp --dport 3306 -j REJECT --reject-with tcp-reset

$ipt -A INPUT -p icmp --icmp-type 8 -j DROP

# windows shares. again.
$ipt -A FORWARD -p tcp --dport 135:139 -j REJECT --reject-with tcp-reset
$ipt -A FORWARD -p udp --dport 135:139 -j DROP
$ipt -A FORWARD -p tcp --dport 445 -j REJECT --reject-with tcp-reset
$ipt -A FORWARD -p udp --dport 445 -j DROP
$ipt -A FORWARD -p udp --dport 520 -j DROP

$ipt -A FORWARD -p tcp --dport  113 -j REJECT --reject-with tcp-reset
$ipt -A FORWARD -p tcp --dport  161 -j REJECT --reject-with tcp-reset
$ipt -A FORWARD -p tcp --dport 3306 -j REJECT --reject-with tcp-reset

# messenger spam
$ipt -A FORWARD -p udp --dport 1026 -j DROP

$ipt -A FORWARD -p icmp --icmp-type 8 -j DROP

# don't log martians on pptp tunnels
$ipt -A FORWARD -i ppp+ -s ! 192.168.3.0/24 -j REJECT --reject-with icmp-admin-prohibited

# log unknown packets with a limit
$ipt -A INPUT -m state --state INVALID -j REJECT --reject-with icmp-port-unreachable
#$ipt -A INPUT -p tcp -j LOG -m limit --limit 1/sec --log-prefix "I-unknown:"
$ipt -A INPUT -p tcp -j REJECT --reject-with tcp-reset
$ipt -A INPUT -j REJECT --reject-with icmp-port-unreachable
$ipt -A INPUT -j DROP
$ipt -A FORWARD -m state --state INVALID -j REJECT --reject-with icmp-port-unreachable
#$ipt -A FORWARD -p tcp -j LOG -m limit --limit 1/sec --log-prefix "F-unknown:"
$ipt -A FORWARD -p tcp -j REJECT --reject-with tcp-reset
$ipt -A FORWARD -j REJECT --reject-with icmp-port-unreachable
$ipt -A FORWARD -j DROP
#$ipt -A OUTPUT -j LOG -m limit --limit 1/sec --log-prefix "O-unknown:"
""")
