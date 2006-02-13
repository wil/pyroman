"""
We'll define some standard services now.
Usually, you could just give the port spec in the allow rules, but sometimes
it's more convenient to have an alias name, and you can also do grouping here.

Ports can be given with their names (as of /etc/services), with port ranges
(in iptables syntax, i.e. 12:34) trailed by their protocol
"""
### these are very common services
# Ping
add_service("ping", dports="echo-request/icmp")
# Secure Shell
add_service("ssh", dports="ssh/tcp")
# Domain Name Server
add_service("dns", dports="domain/udp")
# Network Time Protocol
add_service("ntp", dports="ntp/udp")
# Auth / Ident service. Mainy used for IRC nowadays
add_service("auth", dports="auth/tcp")
# HTTP and HTTPS on different ports
add_service("http", dports="www/tcp")
add_service("https", dports="https/tcp")
add_service("http81", dports="81/tcp")
# FTP
add_service("ftp", dports="ftp/tcp")
# Email protocols
add_service("smtp", dports="smtp/tcp")
add_service("ssmtp", dports="ssmtp/tcp")
add_service("pop3", dports="pop3/tcp")
add_service("pop3s", dports="pop3s/tcp")
add_service("imap", dports="imap/tcp")
add_service("imaps", dports="imaps/tcp")
# LDAP
add_service("ldap", dports="ldap/tcp")
# Heartbeat pings
add_service("heartb", dports="694/udp")
# OpenVPN tunnel
add_service("openvpn", dports="1194/udp")
# DHCP
add_service("dhcp", sports="bootpc/udp", dports="bootps/udp")

# some aliases / groups for convenience
add_service("www", include="http https")
add_service("mail", include="smtp ssmtp pop3 pop3s imap imaps")

# Windows shares are really annoying
add_service("win1t", sports="137:139/tcp 445/tcp")
add_service("win2t", dports="137:139/tcp 445/tcp")
add_service("win1u", sports="137:139/udp 445/udp")
add_service("win2u", dports="137:139/udp 445/udp")
add_service("win", include="win1t win2t win1u win2u")
# Voice over IP
# These are not reliable - some ports are assigned dynamically...
# We rely on our SIP gateway to pick source ports between 7070 and 7080...
# Also this will allow connections from any source to any destination port
# given below, you could probably nail this down to signaling and data
# separately. On the long run, a connection tracking helper would be more
# helpful; otherwise you might need to completely expose your VoIP server.
add_service("sipout", dports="5060/udp 6112/udp 7070:7080/udp 8000/udp")
add_service("sipin",
	dports="3478/udp 8000:65000/udp",
	sports="3479/udp 5060/udp 15060/udp 6112/udp 7070:7080/udp 8000/udp"
)
add_service("voip", include="sipout sipin")

# Typical filesharing ports
add_service("fshar1", dports="6882/tcp")
add_service("fshare", include="fshar1")
