"""
These are the iptables builtin chains.
In order to use the builtins in Pyroman, we need to define objects for them.
Note how we set chain policies!
"""
add_chain("INPUT",                     default="DROP")
add_chain("OUTPUT",                    default="DROP")
add_chain("FORWARD",                   default="DROP")
add_chain("OUTPUT",      id="natOUT",  default="ACCEPT", table="nat")
add_chain("PREROUTING",  id="natPRE",  default="ACCEPT", table="nat")
add_chain("POSTROUTING", id="natPOST", default="ACCEPT", table="nat")
add_chain("INPUT",       id="manIN",   default="ACCEPT", table="mangle")
add_chain("OUTPUT",      id="manOUT",  default="ACCEPT", table="mangle")
add_chain("FORWARD",     id="manFWD",  default="ACCEPT", table="mangle")
add_chain("PREROUTING",  id="manPRE",  default="ACCEPT", table="mangle")
add_chain("POSTROUTING", id="manPOST", default="ACCEPT", table="mangle")
