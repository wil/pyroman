"""
These are some annoying and some usually helpful ICMP messages we want to
allow, but this depends a lot on your level of paranoia.
For example the time-exceeded and destination-unreachable messages
could be used to shut down existing network connections of yours, on the
other hand, if you filter them you'll have to always wait for a timeout.
"""
iptables("INPUT",  "-p icmp --icmp-type router-advertisement -j DROP")
iptables("INPUT",  "-p icmp --icmp-type destination-unreachable -j ACCEPT")
iptables("INPUT",  "-p icmp --icmp-type time-exceeded -j ACCEPT")
iptables("OUTPUT", "-p icmp --icmp-type destination-unreachable -j ACCEPT")
iptables("OUTPUT", "-p icmp --icmp-type time-exceeded -j ACCEPT")
iptables("FORWARD","-p icmp --icmp-type destination-unreachable -j ACCEPT")
iptables("FORWARD","-p icmp --icmp-type time-exceeded -j ACCEPT")
