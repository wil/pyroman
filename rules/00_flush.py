"""
These are basic rules to reset the firewall to an "empty" state,
by emptying any chain and removing them
"""
append_rule_early("""
# reset filter chains
$ipt -P INPUT   DROP
$ipt -P OUTPUT  DROP
$ipt -P FORWARD DROP
$ipt -F
$ipt -X
# reset nat chains
$ipt -t nat -P OUTPUT  ACCEPT
$ipt -t nat -P PREROUTING ACCEPT
$ipt -t nat -P POSTROUTING ACCEPT
$ipt -t nat -F
$ipt -t nat -X
# reset mangle chains
$ipt -t mangle -P INPUT   ACCEPT
$ipt -t mangle -P OUTPUT  ACCEPT
$ipt -t mangle -P FORWARD ACCEPT
$ipt -t mangle -P PREROUTING ACCEPT
$ipt -t mangle -P POSTROUTING ACCEPT
$ipt -t mangle -F
$ipt -t mangle -X
""")
