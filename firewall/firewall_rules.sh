#!/bin/sh -e
#
# Super fancy Firewall 
#

pve-firewall restart

##
# Reset the firewall 
iptables -F
iptables -X
#iptables -t nat -F
#iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT


##
# Firewall Mode 
##
# Mode 1: Allow all traffic to the Honeypots 
# Mode 2: Allow only the listed port (hp_tcp, hp_udp) 
# Mode 3: Block the Honeypots  
MODE=1

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
# Honeypots IP Addresses
hpIPs='172.20.0.2 172.20.0.3'


##
# Ports to open on HP OpenVZ Host
tcp_ports='22' 
udp_ports=''


########### DO NOT CHANGE ###############
trusted_ip='10.0.0.0/8'
#########################################

# Default policy
/sbin/iptables -F INPUT
/sbin/iptables -P INPUT DROP
/sbin/iptables -F FORWARD
/sbin/iptables -P FORWARD DROP
/sbin/iptables -A FORWARD -s 0.0.0.0/0.0.0.0 -d 0.0.0.0/0.0.0.0 -m state --state INVALID -j DROP
/sbin/iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -F OUTPUT
/sbin/iptables -P OUTPUT ACCEPT


####################
## Proxmox Host ##
####################

# Allow loopback
/sbin/iptables -A INPUT -i lo -j ACCEPT

# Allow TCP port listed in tcp_ports 
for i in $tcp_ports;
do
    for ip in $trusted_ip;
    do
        /sbin/iptables -A INPUT -s $ip -p tcp --dport $i -m state --state NEW -j ACCEPT
    done
done

# Allow UDP port listed in udp_ports
for i in $udp_ports;
do
    for ip in $trusted_ip;
    do
        /sbin/iptables -A INPUT -s $ip -p udp -m udp --dport $i -j ACCEPT
    done
done

# Allow related/established connections
/sbin/iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT


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
# /sbin/iptables -A FORWARD -i vmbr0 -d 172.20.0.2 -p tcp --dport 22 -j DROP              #
#    will block SSH traffic to 172.20.0.2)                                                #
#                                                                                         #
# /sbin/iptables -A FORWARD -i vmbr0 -s 8.8.8.8 -d 172.20.0.2 -p tcp --dport 22 -j DROP   #
#    will block SSH traffic to 172.20.0.2 coming from 8.8.8.8 only)                       #
###########################################################################################

# Block container to container communication
/sbin/iptables -A FORWARD -i vmbr0 -o vmbr0 -s 172.20.0.1 -d 172.20.0.0/16 -j ACCEPT # Accept connection from host to honeypots
/sbin/iptables -A FORWARD -i vmbr0 -o vmbr0 -s 172.20.0.0/16 -d 172.20.0.1 -j ACCEPT # Accept connection form honeypots to host
/sbin/iptables -A FORWARD -i vmbr0 -o vmbr0 -s 172.20.0.0/16 -d 172.20.0.0/16 -j DROP

# MODE 1: Allow everything on vmbr0 (to the Honeypots Containers) 
if [ "$MODE" -eq 1 ]; then
echo "DEBUG: Firewall MODE 1"
for i in $hpIPs;
do
        /sbin/iptables -A FORWARD -d $i -j ACCEPT
done
fi 

# MODE 2: Allow only certain ports
if [ "$MODE" -eq 2 ]; then
echo "DEBUG: Firewall MODE 2"
for i in $hp_tcp;
do
    for j in $hpIPs;
    do
            /sbin/iptables -A FORWARD -d $j -p tcp --dport $i -m state --state NEW -j ACCEPT
    done
done

for i in $hp_upd;
do
       for j in $hpIPs;
       do
            /sbin/iptables -A FORWARD -p udp -d $j -m udp --dport $i -j ACCEPT
    done 
done

# Allow Ping 
/sbin/iptables -A FORWARD -p icmp -m icmp --icmp-type any -j ACCEPT

fi 

if [ "$MODE" -eq 3 ]; then
    echo "DEBUG: Firewall MODE 3" 
    # Default policy drops all @ FORWARD 
    exit 0
fi

####
## Rate Limiting 
####

# Create a Table udp_flood in iptables (table of actions) 
/sbin/iptables -N udp_flood 
/sbin/iptables -A udp_flood -m limit --limit 10/s --limit-burst 10 -j RETURN 

if [ "$LOG" -eq 1 ]; then 
    /sbin/iptables -A udp_flood -j LOG --log-level info --log-prefix "[FW] Rate Limit Reached: " 
fi

/sbin/iptables -A udp_flood -j DROP 

# Create a Table syn_flood in iptables (table of actions)
/sbin/iptables -N tcp_flood
/sbin/iptables -A tcp_flood -m hashlimit --hashlimit-name TCP_FLOOD --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 20/minute --hashlimit-burst 5 -m state --state NEW -j DROP # Cannot have more than 20 new connections per minute, burst is 5
# A container is not allowed to have more than 512kbytes/second of bandwidth, but permits initially 10mb
/sbin/iptables -A tcp_flood -m hashlimit --hashlimit-name TCP_BANDWIDTH --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-above 1kb/s --hashlimit-burst 1kb -j DROP 

if [ "$LOG" -eq 1 ]; then
    /sbin/iptables -A tcp_flood -j LOG --log-level info --log-prefix "[FW] Rate Limit Reached: "
fi

# Traffic matching UDP/TCP flood goes to the table
/sbin/iptables -I FORWARD 2 -s 172.20.0.0/16 -p udp -j udp_flood
/sbin/iptables -I FORWARD 2 -s 172.20.0.0/16 -p tcp -j tcp_flood

: '
for i in $hpIPs;
do
    # Traffic matching UDP/TCP flood goes to the table
    #/sbin/iptables -A FORWARD -o vmbr0 -s $i -p udp -j syn_flood 
    #/sbin/iptables -A FORWARD -o vmbr0 -s $i -p tcp --syn -j syn_flood 

    # SSH limitations
    /sbin/iptables -A FORWARD -o vmbr0 -s $i -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH 
    if [ "$LOG" -eq 1 ]; then 
         /sbin/iptables -A FORWARD -o vmbr0 -s $i -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 8 --rttl --name SSH -j LOG --log-level info --log-prefix "[FW] SSH SCAN blocked: " 
    fi
    /sbin/iptables -A FORWARD -o vmbr0 -s $i -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 8 --rttl --name SSH -j DROP 

    # RDP limitations
    /sbin/iptables -A FORWARD -o vmbr0 -s $i -p tcp --dport 3389 -m state --state NEW -m recent --set --name RDP 
        if [ "$LOG" -eq 1 ]; then
        /sbin/iptables -A FORWARD -o br0 -s $i -p tcp --dport 3389 -m state --state NEW -m recent --update --seconds 60 --hitcount 8 --rttl --name RDP -j LOG --log-level info --log-prefix "[FW] RDP SCAN blocked: " 
    fi
    /sbin/iptables -A FORWARD -o br0 -s $i -p tcp --dport 3389 -m state --state NEW -m recent --update --seconds 60 --hitcount 8 --rttl --name RDP -j DROP  

    # HTTP limits
    /sbin/iptables  -A FORWARD -o br0 -s $i -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT 
done
'

####
## Outgoing Traffic 
###

# Allow all other HP outgoing traffic
for i in $hpIPs;
do
    /sbin/iptables -A FORWARD -s $i -j ACCEPT
done

exit 0


