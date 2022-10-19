#!/bin/sh -e
#
# "Super fancy Firewall"
# Division of IT
#
#
# To enable the firewall, you may need to enable the br_netfilter kernel module
# by running the following commands:
# modprobe br_netfilter
# sysctl -p /etc/sysctl.conf
#

#pve-firewall restart

##
# Reset the firewall
/sbin/iptables -F
/sbin/iptables -X
#/sbin/iptables -t nat -F
#/sbin/iptables -t nat -X
/sbin/iptables -t mangle -F
/sbin/iptables -t mangle -X
/sbin/iptables -P INPUT ACCEPT
/sbin/iptables -P FORWARD ACCEPT
/sbin/iptables -P OUTPUT ACCEPT

sysctl -w net.bridge.bridge-nf-call-iptables=1

##
# Firewall Mode
##
# Mode 1: Allow all traffic to the Honeypots
# Mode 2: Allow only the listed port (hp_tcp, hp_udp)
# Mode 3: Block the Honeypots
MODE=1

# NOTE: MITM should listen on the $CONTAINER_GATEWAY IP, other IPs will get blocked by this firewall

##
# Container network settings
##
# Update this if your container IP address and network is different
#
CONTAINER_NETWORK="10.0.3.1/24"
CONTAINER_GATEWAY="10.0.3.1"
CONTAINER_INTERFACE="lxcbr0"

##
# Rate Limiting Logging
##
# 0: No logging (default)
# 1: All the traffic dropped because of the rate limiting rules is logged in Syslog (can generate a lot of logs!)
LOG=0

##
# MODE=2: Ports to Open on the Honeypots
hp_tcp='22'
hp_udp=''

##
# Ports to open on the Host
host_tcp='22'
host_udp=''

########### DO NOT CHANGE ###############
trusted_ip='172.30.0.0/16 10.255.0.0/16 192.168.11.0/24'
#########################################

# Default policy
/sbin/iptables -F INPUT
/sbin/iptables -P INPUT DROP
/sbin/iptables -F FORWARD
/sbin/iptables -P FORWARD DROP
/sbin/iptables -A FORWARD -s 0.0.0.0/0.0.0.0 -d 0.0.0.0/0.0.0.0 -m state --state INVALID -j DROP -m comment --comment "Drop invalid connections"
/sbin/iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Allow existing connections"
/sbin/iptables -F OUTPUT
/sbin/iptables -P OUTPUT ACCEPT


####################
## Host ##
####################

# Allow lxc-net service
/sbin/iptables -A INPUT -i $CONTAINER_INTERFACE -p tcp -m tcp --dport 53 -j ACCEPT -m comment --comment "Container Network DNS TCP"
/sbin/iptables -A INPUT -i $CONTAINER_INTERFACE -p udp -m udp --dport 53 -j ACCEPT -m comment --comment "Container Network DNS UDP"
/sbin/iptables -A INPUT -i $CONTAINER_INTERFACE -p tcp -m tcp --dport 67 -j ACCEPT -m comment --comment "Container Network DHCP TCP"
/sbin/iptables -A INPUT -i $CONTAINER_INTERFACE -p udp -m udp --dport 67 -j ACCEPT -m comment --comment "Container Network DHCP UDP"
/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment "Allow local loopback"

# Allow TCP port listed in host_tcp
for i in $host_tcp;
do
    for ip in $trusted_ip;
    do
        /sbin/iptables -A INPUT -s "$ip" -p tcp --dport $i -m state --state NEW -j ACCEPT
    done
done

# Allow UDP port listed in host_udp
for i in $host_udp;
do
    for ip in $trusted_ip;
    do
        /sbin/iptables -A INPUT -s "$ip" -p udp -m udp --dport $i -j ACCEPT
    done
done

# Allow connections to the host on the private ip $CONTAINER_GATEWAY (for the MITM)
/sbin/iptables -A INPUT -d $CONTAINER_GATEWAY -p tcp ! --dport 22 -j ACCEPT -m comment --comment "Allow connections to the host for MITM"
/sbin/iptables -A INPUT -d 127.0.0.1 -p tcp ! --dport 22 -j ACCEPT -m comment --comment "Allow connections to localhost for MITM"

# Allow related/established connections
/sbin/iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT -m comment --comment "Allow related/established connections"

###############
## Honeypots ##
###############


####
## Honeypot Incoming Traffic
####


############### HERE is a good place to block incoming/outgoing traffic ###################
#                                                                                         #
# To block some traffic for one honeypot, use the -d <Honeypot Private IP> parameter      #
# To block some Internet IP, use the -s <Attacker Public IP> parameter                    #
#                                                                                         #
# for example:                                                                            #
# /sbin/iptables -A FORWARD -i lxcbr0 -d 172.20.0.2 -p tcp --dport 22 -j DROP              #
#    will block SSH traffic to 172.20.0.2)                                                #
#                                                                                         #
# /sbin/iptables -A FORWARD -i lxcbr0 -s 8.8.8.8 -d 172.20.0.2 -p tcp --dport 22 -j DROP   #
#    will block SSH traffic to 172.20.0.2 coming from 8.8.8.8 only)                       #
###########################################################################################

# Block container to container communication
/sbin/iptables -A FORWARD -i $CONTAINER_INTERFACE -o $CONTAINER_INTERFACE -s $CONTAINER_GATEWAY -d $CONTAINER_NETWORK -j ACCEPT -m comment --comment "Accept connection from host to honeypots"
/sbin/iptables -A FORWARD -i $CONTAINER_INTERFACE -o $CONTAINER_INTERFACE -s $CONTAINER_NETWORK -d $CONTAINER_GATEWAY -j ACCEPT -m comment --comment "Accept connection from honeypots to host"
/sbin/iptables -A FORWARD -i $CONTAINER_INTERFACE -o $CONTAINER_INTERFACE -s $CONTAINER_NETWORK -d $CONTAINER_NETWORK -j DROP -m comment --comment "Drop connection between honeypots"

# Forward container traffic for lxc-net
/sbin/iptables -A FORWARD -o $CONTAINER_INTERFACE -j ACCEPT -m comment --comment "Forward Container traffic"
/sbin/iptables -A FORWARD -i $CONTAINER_INTERFACE -j ACCEPT -m comment --comment "Forward Container traffic"

# MODE 1: Allow everything on $CONTAINER_INTERFACE (to the Honeypots Containers)
if [ "$MODE" -eq 1 ]; then
echo "DEBUG: Firewall MODE 1"
/sbin/iptables -A FORWARD -d $CONTAINER_NETWORK -j ACCEPT -m comment --comment "Allow connections to the honeypots"
fi

# MODE 2: Allow only certain ports
if [ "$MODE" -eq 2 ]; then
echo "DEBUG: Firewall MODE 2"
for i in $hp_tcp;
do
	/sbin/iptables -A FORWARD -d $CONTAINER_NETWORK -p tcp --dport $i -m state --state NEW -j ACCEPT
done

for i in $hp_udp;
do
	/sbin/iptables -A FORWARD -p udp -d $CONTAINER_NETWORK -m udp --dport $i -j ACCEPT
done

fi

if [ "$MODE" -eq 3 ]; then
    echo "DEBUG: Firewall MODE 3"
    # Default policy drops all @ FORWARD
    exit 0
fi

# Allow Ping
/sbin/iptables -A FORWARD -p icmp -m icmp --icmp-type any -j ACCEPT -m comment --comment "Allow ICMP (Ping)"

####
## Rate Limiting
####

# Create a Table udp_flood in iptables (table of actions)
/sbin/iptables -N udp_flood
/sbin/iptables -A udp_flood -m hashlimit --hashlimit-name UDP_FLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-upto 60/minute --hashlimit-burst 10 -j RETURN

if [ "$LOG" -eq 1 ]; then
    /sbin/iptables -A udp_flood -j LOG --log-level info --log-prefix "[FW] Rate Limit Reached: "
fi

/sbin/iptables -A udp_flood -j DROP

# Create a Table syn_flood in iptables (table of actions)
/sbin/iptables -N tcp_flood
/sbin/iptables -A tcp_flood -m hashlimit --hashlimit-name TCP_FLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-upto 60/minute --hashlimit-burst 10 -m state --state NEW -j RETURN # Cannot have more than 60 new connections per minute, burst is 10
# A container is not allowed to have more than 512kbytes/second of bandwidth
#/sbin/iptables -A tcp_flood -m hashlimit --hashlimit-name TCP_BANDWIDTH --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 8/sec --hashlimit-burst 8 -j DROP

if [ "$LOG" -eq 1 ]; then
    /sbin/iptables -A tcp_flood -j LOG --log-level info --log-prefix "[FW] Rate Limit Reached: "
fi

/sbin/iptables -A tcp_flood -j DROP

# Traffic matching UDP/TCP flood goes to the table
/sbin/iptables -I FORWARD 3 -s $CONTAINER_NETWORK -p udp -j udp_flood
/sbin/iptables -I FORWARD 3 -s $CONTAINER_NETWORK -p tcp -j tcp_flood

####
## Outgoing Traffic
###

# Allow all other HP outgoing traffic
/sbin/iptables -A FORWARD -s $CONTAINER_NETWORK -j ACCEPT -m comment --comment "Allow all other honeypot outgoing"

exit 0


