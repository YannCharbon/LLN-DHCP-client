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