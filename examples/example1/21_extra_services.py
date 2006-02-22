"""
We'll define some extra services here.
"""
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

# Typical filesharing ports - Bittorrent
add_service("bittor", dports="6880:6890/tcp 696/tcp 16880:16882/tcp")
add_service("fshare", include="bittor")
