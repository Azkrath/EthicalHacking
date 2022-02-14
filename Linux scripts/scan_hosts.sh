#!/bin/bash
#
# Script to enumerate live hosts with nmap
# Made by FM
#
# Use sudo to allow nmap to use ARP to discover hosts as well as ICMP
# Examples: 
# - sudo ./scan_hosts.sh 10.0.0.0/24 (scan a single subnet)
# - cat host_list.txt | sudo ./scan_hosts.sh `xargs` (scan a list of subnets)

search="/"
for ip in "$@"
do
	host=${ip%"$search"*}
	subnet=${ip#"$host"}
	base=${host%.*}.
	nmap -sP "$ip" | grep $base"*" | awk -v s=$base '/s/{print $NF}' | sed 's/[(),]//g' | sed 's/$/,/' > "$host"_hosts.txt
done
