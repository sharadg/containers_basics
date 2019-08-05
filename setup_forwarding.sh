
sysctl -w net.ipv4.ip_forward=1
iptables -A FORWARD -s 10.240.0.0/16 -j ACCEPT
iptables -A FORWARD -d 10.240.0.0/16 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.240.0.0/24 ! -o cni0 -j MASQUERADE

# Make sure that ip_forwarding is enabled at the kernel level
# cat /proc/sys/net/ipv4/ip_forward
# 1


# In order to troubleshoot iptables rules

# delete existing rules

# sudo iptables -t nat -D PREROUTING -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (PREROUTING): "
# sudo iptables -t nat -D POSTROUTING -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (POSTROUTING): "
# sudo iptables -t filter -D FORWARD -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (FORWARD): "

# Insert logging rules to capture at /var/log/kern.log

# sudo iptables -t nat -A PREROUTING -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (PREROUTING): "
# sudo iptables -t nat -I POSTROUTING 1 -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (POSTROUTING):"
# sudo iptables -t filter -I FORWARD 1 -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (FORWARD): "
# sudo iptables -t filter -I FORWARD 2 -d 10.240.0.0/24 -j LOG --log-prefix "ICMP (FORWARD dest): "

# optionally, you can also experiment with appending the logging rule to tne end of the chain
# sudo iptables -t nat -A POSTROUTING -s 10.240.0.0/24 -j LOG --log-prefix "ICMP (POSTROUTING): "
