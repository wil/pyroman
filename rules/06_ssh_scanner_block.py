"""
NOTE: this rule contains an interface name (ethEXT) hardcoded!

SSH scanners are rather annyoing and may pose a security risk if you are
unable to enforce a good password policy on all you machines.

The following rules (with optional logging) will drop incoming SSH
connections on a per-host basis if they come in too quickly.
The rate of 5/60s is arbitrary, but worked just fine to make SSH scanners
give up without interrupting regular users at all and without allowing
to many brute-force tries.

Note that if you e.g. have a script which will log in to many SSH servers
quickly, you should either whitelist your source host or disable this, since
such a script can easily trigger these rules.
"""
iptables("INPUT", "-i ethEXT -p tcp --dport 22 -m state --state NEW \
        -m recent --set --name SSH")
iptables("FORWARD","-i ethEXT -p tcp --dport 22 -m state --state NEW \
        -m recent --set --name SSH")
# uncomment to log
#iptables("INPUT", "-i ethEXT -p tcp --dport 22 -m state --state NEW \
#        -m recent --update --seconds 60 --hitcount 5 --rttl \
#        --name SSH -j LOG --log-prefix \"SSH_brute_force \"")
#iptables("FORWARD", "-i ethEXT -p tcp --dport 22 -m state --state NEW \
#        -m recent --update --seconds 60 --hitcount 5 --rttl \
#        --name SSH -j LOG --log-prefix \"SSH_brute_force \"")
# Drop connections when they hit the treshold
iptables("INPUT",  "-i ethEXT -p tcp --dport 22 -m state --state NEW \
        -m recent --update --seconds 60 --hitcount 5 --rttl --name SSH -j DROP")
iptables("FORWARD","-i ethEXT -p tcp --dport 22 -m state --state NEW \
        -m recent --update --seconds 60 --hitcount 5 --rttl --name SSH -j DROP")
