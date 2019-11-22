============================
Mon(IoT)r EXPERIMENT MANAGER
============================

1) Copy the content of this directory to any location, for example on /opt/moniotr

2) Install the following Ubuntu dependences:
apt install python3 python3-pip isc-dhcp-server tcpdump

3) Install the following python dependence and modification (please do NOT use a different version of mitmproxy):
pip3 install mitmproxy==4.0.4
cp lib/server.py /usr/local/lib/python3.6/dist-packages/mitmproxy/proxy/

4) Configure app-armor in such a way that dhcpd is excluded:
mkdir /etc/apparmor.d/disable
ln -s /etc/apparmor.d/usr.sbin.dhcpd /etc/apparmor.d/disable/usr.sbin.dhcpd
service apparmor restart

5) Configure netplan and isc-dhcp-server for the network interfaces that will host the monitored devices.
For each monitored network, add to dhcpd.conf the following lines inside the "subnet" block:

on commit {
    set clip = binary-to-ascii(10, 8, ".", leased-address);
    set clhw = binary-to-ascii(16, 8, ":", substring(hardware, 1, 6));
    execute("/opt/moniotr/bin/setup-device", clip, clhw);
}

If Mon(IoT)r was not installed in /opt/moniotr, replace /opt/moniotr with the installation directory.

Finally, restart isc-dhcp-server:
service isc-dhcp-server restart


6) Copy etc/moniotr.conf.example to etc/moniotr.conf and edit its values according to the local configuration
of the system.

7) You can start Mon(IoT)r using:

/opt/moniotr/bin/moniotr-ctrl start

The same command can be added to /etc/rc.local to activate Mon(IoT)r at startup
If Mon(IoT)r was not installed in /opt/moniotr, replace /opt/moniotr with the installation directory.

8) You can find example configuration files for netplan, hostapd (in case of use Wi-Fi access point),
isc-dhcp-server, iptables-save, and sysctl in the examples directory. 

====================================
APPENDIX 1. Configuring DNS override
====================================

NOTE: this is an experimental feature, not covered in the manual.

1) Edit moniotr.conf and add the new configuration options from moniotr.conf.example:
DNS_OVERRIDE="false"
NAMED_VIEWS="$MONIOTR_DIR/var/named.views"
NAMED_RPZ_DIR="$MONIOTR_DIR/var/named-rpz"
NAMED_PORT="53"
(see moniotr.conf.example for more explanations on what these options do)

2) Install bind9
apt-get install bind9

3) Configure bind9
open /etc/bind/named.conf comment all the lines, and add the following line (don't forget the semicolon!):

include "/opt/moniotr/etc/named.conf";

As usual, change the path if Mon(IoT)r is installed on a different directory.

4) Configure app-armor in such a way that bind9 is excluded:
mkdir /etc/apparmor.d/disable
ln -s /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/disable/usr.sbin.named
service apparmor restart

5) Set bind9 DNS forwarders (optional)
If you want to change the default Google DNS:
open /opt/moniotr/etc/named.conf and replace the IP addresses in the "forwarding" sections with the new DNS
forwarded you want to use

6) Set bind9 views file (optional)
If the NAMED_VIEWS option in moniotr.conf is "/opt/moniotr/var/named.views" (default value), 
this step is not necessary. If the value is different, you have to update the last line of "/opt/moniotr/etc/named.conf"
with the new NAMED_VIEWS path:

include "/opt/moniotr/var/named.views";

7) Set the option DNS_OVERRIDE option in moniotr.conf to "true" (its default value was "false")

8) Restart Mon(IoT)r using:
/opt/moniotr/bin/moniotr-ctrl restart

To disable DNS override, just set the DNS_OVERRIDE option back to off and restart the networking component:
networking-ctrl restart.

NOTE: DNS override will intercept all DNS requests from the monitored networks, 
      there is no need to change the DHCP configuration.
