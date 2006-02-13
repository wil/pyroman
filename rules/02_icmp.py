"""
These are some annoying and some usually helpful ICMP messages we want to
allow, but this depends a lot on your level of paranoia.
For example the time-exceeded and destination-unreachable messages
could be used to shut down existing network connections of yours, on the
other hand, if you filter them you'll have to always wait for a timeout.
"""
append_rule_early("""
$ipt -A INPUT   -p icmp --icmp-type router-advertisement -j DROP
$ipt -A INPUT   -p icmp --icmp-type destination-unreachable -j ACCEPT
$ipt -A INPUT   -p icmp --icmp-type time-exceeded -j ACCEPT
$ipt -A OUTPUT  -p icmp --icmp-type destination-unreachable -j ACCEPT
$ipt -A OUTPUT  -p icmp --icmp-type time-exceeded -j ACCEPT
$ipt -A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT
$ipt -A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT
""")
