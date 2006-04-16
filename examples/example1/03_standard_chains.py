"""
Pyroman uses some standard chains, set in it's config.
These chains are used by the "allow()", "reject()" and "drop()" commandos
for nicer rule writing, and probably should do exactly that.

If you want maximal performance, you'll want to change these to ACCEPT and DROP
directly by calling 'Firewall.accept = "ACCEPT"' and removing the lines below.

The (small) benefits of using this approach is that you can easily disable
the rules (by modifying 'drop' and 'reject') without reloading your firewall
and that you get complete traffic counters in these chains.

The variables "Firewall.accept", "Firewall.drop" and "Firewall.reject" are
used here, so you can change them in one place only.
"""
add_chain(Firewall.accept)
# Kernel and iptables can do new string matches?
if Firewall.iptables_version(min="1.3.4") and \
	Firewall.kernel_version(min="2.6.12"):
	# Drop bittorrent traffic
	iptables(Firewall.accept, '-m string --string "BitTorrent protocol" ' + \
		'--algo bm --from 0 --to 100 -j DROP')
# add accept default rule to the chain
iptables(Firewall.accept, "-j ACCEPT")

# this is a silent drop
add_chain(Firewall.drop)
iptables(Firewall.drop, "-j DROP")

# .. these are clean "reject" rules (i.e. send 'connection refused' back)
add_chain(Firewall.reject)
iptables(Firewall.reject, "-p tcp -j REJECT --reject-with tcp-reset")
iptables(Firewall.reject, "-j REJECT")
