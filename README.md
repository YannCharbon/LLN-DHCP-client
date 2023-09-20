Basic Linux DHCP client using Rapid Commit supporting Low-power and Lossy Networks
===========

This DHCP client is capable to work behind the Mbed OS Nanostack network stacks, such as Wi-SUN, Thread
or 6LoWPAN mesh. This allows to connect a standard PC behind such networks. As it does not use any
additional library, this DHCP client is very easy to deploy on any Linux system.

E.g. using Nanostack border router, it is possible to have the following setup :

<pre style="text-align:center">
.-----------------.      .-------------------------.      .------------------------.      .---------.
| Internet (IPv6) | <--> |  Nanostack BR (Wi-SUN)  | <--> |  Modified Router Node  | <--> |  Linux  |
'-----------------'      '-------------------------'      '------------------------'      '---------'
</pre>



## Usage

The syntax to run the DHCP client is the following:

<pre>
sudo ./dhcp-client [options]
</pre>

Options are the following:

- Interface name

## Additional information
### Correct network configuration

The DHCP client requires the target interface not to be managed by another network manager. Thus, other DHCP
clients should be disabled (at least on the target interface). The interface addressing mode should be set to
"link-local only" as DHCP requests use link-local addressing (fe80::). Depending on the platform you are using,
this configuration can be set using the network manager, or by editing `/etc/network/interfaces` if it is available.

Here is an example configuration for `/etc/network/interfaces` which sets automatic link-local address on eth0.

<pre>
allow-hotplug eth0
iface eth0 inet6 manual
	pre-up /sbin/sysctl -q -w net.ipv6.conf.eth0.autoconf=1
	pre-up /sbin/sysctl -q -w net.ipv6.conf.eth0.accept_ra=2
</pre>

### Using client as a service

Here is a template to run the DHCP client as a service (using systemd).

<pre>
# Put this file inside /etc/systemd/system/

[Unit]
Description=Low-Power and Lossy network DHCP client service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=[path to lln-dhcp-client executable] eth0

[Install]
WantedBy=multi-user.target
Alias=lln-dhcp-client.service
</pre>