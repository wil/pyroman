"""
There are some well-known "stealth" port scans that we'd like to get rid
of. These tcp flag combinations are invalid and can be just dropped early.
"""
iptables("manPRE","-p tcp --tcp-flags ALL FIN,URG,PSH -j DROP")
iptables("manPRE","-p tcp --tcp-flags ALL NONE -j DROP")
iptables("manPRE","-p tcp --tcp-flags SYN,RST SYN,RST -j DROP")
iptables("manPRE","-p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP")
