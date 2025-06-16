#! /bin/sh
#
# Dodajte ili modificirajte pravila na oznacenim mjestima ili po potrebi (i želji) na 
# nekom drugom odgovarajucem mjestu (pazite: pravila se obrađuju slijedno!)
#
IPT=/sbin/iptables

$IPT -P INPUT  DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD

$IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

#
# za potrebe testiranja dozvoljen je ICMP (ping i sve ostalo)
#
$IPT -A INPUT   -p icmp -j ACCEPT
$IPT -A FORWARD -p icmp -j ACCEPT
$IPT -A OUTPUT  -p icmp -j ACCEPT

#
# Primjer "anti spoofing" pravila na sucelju eth0
#
#$IPT -A INPUT   -i eth0 -s 127.0.0.0/8  -j DROP
#$IPT -A FORWARD -i eth0 -s 127.0.0.0/8  -j DROP
#$IPT -A INPUT   -i eth0 -s 192.0.2.0/24  -j DROP
#$IPT -A FORWARD -i eth0 -s 192.0.2.0/24  -j DROP
#$IPT -A INPUT   -i eth0 -s 192.168.0.0/24  -j DROP
#$IPT -A FORWARD -i eth0 -s 192.168.0.0/24  -j DROP
#$IPT -A INPUT   -i eth0 -s 192.168.1.2  -j DROP
#$IPT -A FORWARD -i eth0 -s 192.168.1.2  -j DROP

WWW=192.0.2.10
DNS=192.0.2.20
SERVER=203.0.113.10
DATABASE=10.0.0.100
PRIVATE_NET=10.0.0.0/24
ADMIN_IP=192.168.0.20
FW_IP=10.0.0.1


#
# Web poslužitelju (tcp/80 i tcp/443) pokrenutom na www se može 
# pristupiti s bilo koje adrese (iz Interneta i iz lokalne mreže), ...
#
$IPT -A FORWARD -p tcp -d $WWW --dport 80  -j ACCEPT
$IPT -A FORWARD -p tcp -d $WWW --dport 443 -j ACCEPT   # HTTPS

#
# DNS poslužitelju (udp/53 i tcp/53) pokrenutom na dns se može 
# pristupiti s bilo koje adrese (iz Interneta i iz lokalne mreže), ...
#
$IPT -A FORWARD -p udp -d $DNS --dport 53 -j ACCEPT
$IPT -A FORWARD -p tcp -d $DNS --dport 53 -j ACCEPT

#
# ... a SSH poslužiteljima na www i dns samo s admin iz lokalne mreže "Private"
#
$IPT -A FORWARD -p tcp -s $ADMIN_IP -d $WWW --dport 22 -j ACCEPT
$IPT -A FORWARD -p tcp -s $ADMIN_IP -d $DNS --dport 22 -j ACCEPT

#
# S www je dozvoljen pristup poslužitelju database (Private) na TCP portu 10000
# te pristup DNS poslužiteljima u Internetu (UDP i TCP port 53).
#
$IPT -A FORWARD -p tcp -s $WWW -d $DATABASE --dport 10000 -j ACCEPT
$IPT -A FORWARD -p udp -s $WWW             --dport 53    -j ACCEPT
$IPT -A FORWARD -p tcp -s $WWW             --dport 53    -j ACCEPT

#
# ... S www je zabranjen pristup svim ostalim adresama i poslužiteljima.
#
$IPT -A FORWARD -s $WWW -j DROP

#
# DNS čvor smije van samo na 53/udp i 53/tcp, sve ostalo blokiraj.
#
$IPT -A FORWARD -p udp -s $DNS --dport 53 -j ACCEPT
$IPT -A FORWARD -p tcp -s $DNS --dport 53 -j ACCEPT
$IPT -A FORWARD -s $DNS -j DROP

#
# Pristup svim ostalim adresama i poslužiteljima u DMZ je zabranjen.
#
$IPT -A FORWARD -d 192.0.2.0/24 -j DROP


#
# Pristup SSH poslužitelju na cvoru database samo iz mreže Private.
#
$IPT -A FORWARD -p tcp -s $PRIVATE_NET -d $DATABASE --dport 22 -j ACCEPT

#
# Web poslužitelju na cvoru database (port 10000) može pristupiti
# isključivo www iz DMZ-a i hostovi iz Private.
#
$IPT -A FORWARD -p tcp -s $WWW         -d $DATABASE --dport 10000 -j ACCEPT
$IPT -A FORWARD -p tcp -s $PRIVATE_NET -d $DATABASE --dport 10000 -j ACCEPT

#
# S racunala database je zabranjen pristup svim uslugama u Internetu i u DMZ.
#
$IPT -I FORWARD 1 -s $DATABASE -j DROP        # postavi na sam vrh FORWARD-a

#
# S racunala iz Private (osim database) dozvoljen je HTTP(S) i DNS prema Internetu.
#
$IPT -A FORWARD -p tcp -s $PRIVATE_NET --dport 80  -j ACCEPT
$IPT -A FORWARD -p tcp -s $PRIVATE_NET --dport 443 -j ACCEPT
$IPT -A FORWARD -p udp -s $PRIVATE_NET --dport 53  -j ACCEPT
$IPT -A FORWARD -p tcp -s $PRIVATE_NET --dport 53  -j ACCEPT

#
# Pristup iz vanjske mreže u lokalnu LAN mrežu je zabranjen.
#
$IPT -A FORWARD -d $PRIVATE_NET ! -s $PRIVATE_NET -j DROP


# SSH na sam FW dopušten isključivo s hosta admin
$IPT -A INPUT -p tcp -s $ADMIN_IP -d $FW_IP --dport 22 -j ACCEPT

#
# Pristup svim ostalim uslugama (portovima) na cvoru FW je zabranjen.
#
$IPT -A INPUT -p tcp ! --dport 22 -j DROP
