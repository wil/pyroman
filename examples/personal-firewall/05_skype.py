"""
Restrict skype.
This prevents most outgoing connections, which may trigger some corporate
firewalls. This is supposed to prevent your computer from becoming a supernode.

In order to use this, you must create a group "skype" and then set skype to
"setgid skype" so it is run as group skype. (Alternatively, you can use a
separate user to run skype as, and change --gid-owner to --uid-owner below)

If you just blindly add this ruleset, it will likely fail with "Bad value".

If you want to further secure your Skype usage, you might want to also block
access to any local IP addresses. It has been reported that skype can be
tricked into arbitrary connections. So it might allow access to private
services! You should migrate to an open source solution instead.
"""
# Low level iptables rules.
iptables(Firewall.output, "-p tcp -m owner --gid-owner skype -m multiport ! --dports 80,443 -j %s" % Firewall.reject)
iptables(Firewall.output, "-p udp -m owner --gid-owner skype -j %s" % Firewall.reject)
