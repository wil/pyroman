"""
In this example setup, we use named interfaces, as you can achieve by either
udev or ifrename. This is recommended, so your interfaces do not change names
by a kernel upgrade causing the drivers to be loaded in a different order
(and thus assigning different names to your physical interfaces).

This will effect your system on many levels, that's why it should be handled
on a hardware initialization level, and not within Pyroman (we could obviously
lookup interface names by MAC address, but that won't fix your routing!)
"""
add_interface("int", "ethINT tapVPN")
add_interface("dmz", "ethDMZ")
add_interface("ext", "ethEXT")
