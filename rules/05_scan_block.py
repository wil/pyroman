"""
There are some well-known "stealth" port scans that we'd like to get rid
of. These tcp flag combinations are invalid and can be just dropped early.
"""
append_rule_early("""
# Dropping invalid packets (network scans)
# XMAS
$ipt -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
# NULL
$ipt -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
# SYN-RST
$ipt -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# SYN-FIN
$ipt -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
""")
