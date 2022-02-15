#!/usr/bin/python
#coding=utf-8
# Application that detects alive hosts using ICMP
# and does a port scan for every alive target
# by FM
# Python 3
# -------------------------------------
import os, platform, sys, time, re, ipaddress
from datetime import datetime as dt
from subprocess import Popen, PIPE


## Scan an ip address in order to check for host liveness
def ip_scan(ip, ping_cmd, arping_cmd):

    #print("Testing ip " + ip)
    comm1 = ping_cmd + ip
    resp1 = os.popen(comm1)

    status = "DOWN"
    for line in resp1.readlines():
        if(line.upper().count("TTL")):
            status = "UP"
            #print(ip, "--> Live")
            break

    if(status == "DOWN"):
        comm2 = arping_cmd + ip
        resp2 = os.popen(comm2)

        for line in resp2.readlines():
            if(line.upper().count("RTT")):
                status = "UP, NO ICMP"
                #print(ip, "--> Live, NO ICMP")
                break

    ## Get target MAC address
    Popen(["ping", "-c 1", ip], stdout = PIPE)
    pid = Popen(["arp", "-n", ip], stdout = PIPE)
    s = pid.communicate()[0]
    hasMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s.decode())
    if hasMac is not None:
        mac = hasMac.groups()[0]
    else:
        mac = 'None'

    hostname = 'None'
    ## Get hostname
    ## TODO

    ## Set data
    data = (ip,mac,hostname,status)
    if status == "UP":
        print(data)

## MAIN -------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 2:

        try:

            ## Validates if the OS is Windows or other
            ## and sets the appropriate commands
            oper = platform.system()
            timeout = 4
            if(oper == "Windows"):
                ping_cmd = f"ping -n 1 -w {timeout} "
                arping_cmd = f"arp-ping -n 1 "
            else:
                ## Ask for the interface for arping
                interface = input("Enter the interface: ")
                ping_cmd = f"ping -c 1 -t {timeout} "
                arping_cmd = f"arping -c 1 -i {interface}"
                
            ## Set the beginning datetime
            t1 = dt.now()

            subnets = open(sys.argv[1],"r")
            for subnet in subnets:
                subnet = subnet.replace("\n","").replace("\t","")
                ## Run the scanner
                print("Scanning Subnet: ", subnet)

                ## Scans the machines in the defined range
                print("Scanning in Progress")

                hosts = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
                for ip in hosts:
                    ip_scan(ip, ping_cmd, arping_cmd)

            ## Set the ending datetime
            t2 = dt.now()
            
            ## Calculates the scan time and prints it
            total = t2 - t1

            print("Scanning completed in: ",total)

        except KeyboardInterrupt:
            print("Execution interrupted: Ctrl+C")
            sys.exit()

    else:
        print('[-] Usage: ' + sys.argv[0] + ' subnet_list.txt')
