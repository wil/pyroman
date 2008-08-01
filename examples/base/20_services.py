"""
We'll define some standard services now.
Usually, you could just give the port spec in the allow rules, but sometimes
it's more convenient to have an alias name, and you can also do grouping here.

The aliases below will allow you to write e.g. "ssh" instead of "ssh/tcp",
but some aliases are more complex (e.g. the 'mail' alias which covers all
common email ports) or the "www" alias for http and https ports.

"ping" on the other hand is clearly more readable than "echo-request/icmp".

In general it's up to the user whether or not he wants to use these aliases.

Ports can be given with their names (as of /etc/services), with port ranges
(in iptables syntax, i.e. 12:34) trailed by their protocol (12:34/tcp)
"""
### these are shorthands for very common services
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
add_service("www", include="http https")
# FTP
add_service("ftp", dports="ftp/tcp")
# Email protocols
add_service("smtp", dports="smtp/tcp")
add_service("ssmtp", dports="ssmtp/tcp")
add_service("pop3", dports="pop3/tcp")
add_service("pop3s", dports="pop3s/tcp")
add_service("imap", dports="imap/tcp")
add_service("imaps", dports="imaps/tcp")
add_service("submission", dports="submission/tcp")
add_service("mail", include="smtp ssmtp pop3 pop3s imap imaps")
# LDAP
add_service("ldap", dports="ldap/tcp")
# Heartbeat pings
add_service("heartb", dports="694/udp")
# OpenVPN tunnel
add_service("openvpn", dports="1194/udp")
# DHCP
add_service("dhcp", sports="bootpc/udp", dports="bootps/udp")
# Multicast DNS / Bonjour / Rendevouz / Avahi
add_service("mdns", sports="5353/udp", dports="5353/udp")

# Windows shares are really annoying
# this is a set of 4 ports on two protocols and two directions each...
add_service("winTCPin", sports="137:139/tcp 445/tcp")
add_service("winTCPout", dports="137:139/tcp 445/tcp")
add_service("winUDPin", sports="137:139/udp 445/udp")
add_service("winUDPout", dports="137:139/udp 445/udp")
add_service("win", include="winTCPin winTCPout winUDPin winUDPout")

# unprivileged ports
add_service("unprivileged", dports="1024:65535/tcp 1024:65535/udp")
