# silently drop routing announcements
iptables("INPUT", "-p udp --dport route -j DROP")
# drop windows shares
iptables("INPUT", "-p tcp --dport 135:139 -j REJECT --reject-with tcp-reset")
iptables("INPUT", "-p udp --dport 135:139 -j DROP")
iptables("INPUT", "-p tcp --dport 445 -j REJECT --reject-with tcp-reset")
iptables("INPUT", "-p udp --dport 445 -j DROP")
# messenger spam
iptables("INPUT", "-p udp --dport 1026 -j DROP")

iptables("INPUT", "-p tcp --dport  113 -j REJECT --reject-with tcp-reset")
iptables("INPUT", "-p tcp --dport  161 -j REJECT --reject-with tcp-reset")
iptables("INPUT", "-p tcp --dport 3306 -j REJECT --reject-with tcp-reset")

iptables("INPUT", "-p icmp --icmp-type 8 -j DROP")

# windows shares. again.
iptables("FORWARD", "-p tcp --dport 135:139 -j REJECT --reject-with tcp-reset")
iptables("FORWARD", "-p udp --dport 135:139 -j DROP")
iptables("FORWARD", "-p tcp --dport 445 -j REJECT --reject-with tcp-reset")
iptables("FORWARD", "-p udp --dport 445 -j DROP")
iptables("FORWARD", "-p udp --dport 520 -j DROP")

iptables("FORWARD", "-p tcp --dport  113 -j REJECT --reject-with tcp-reset")
iptables("FORWARD", "-p tcp --dport  161 -j REJECT --reject-with tcp-reset")
iptables("FORWARD", "-p tcp --dport 3306 -j REJECT --reject-with tcp-reset")

# messenger spam
iptables("FORWARD", "-p udp --dport 1026 -j DROP")

iptables("FORWARD", "-p icmp --icmp-type 8 -j DROP")

# log unknown packets with a limit
iptables("INPUT", "-m state --state INVALID -j REJECT --reject-with icmp-port-unreachable")
#iptables("INPUT", "-p tcp -j LOG -m limit --limit 1/sec --log-prefix "I-unknown:"")
iptables("INPUT", "-p tcp -j REJECT --reject-with tcp-reset")
iptables("INPUT", "-j REJECT --reject-with icmp-port-unreachable")
iptables("INPUT", "-j DROP")
iptables("FORWARD", "-m state --state INVALID -j REJECT --reject-with icmp-port-unreachable")
#iptables("FORWARD", "-p tcp -j LOG -m limit --limit 1/sec --log-prefix "F-unknown:"")
iptables("FORWARD", "-p tcp -j REJECT --reject-with tcp-reset")
iptables("FORWARD", "-j REJECT --reject-with icmp-port-unreachable")
iptables("FORWARD", "-j DROP")
#iptables("OUTPUT", "-j LOG -m limit --limit 1/sec --log-prefix "O-unknown:"")
