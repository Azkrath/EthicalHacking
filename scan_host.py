#!/usr/bin/python
#coding=utf-8
# Application that detects alive hosts using ICMP
# and does a port scan for every alive target
# by FM
# Python 3
# -------------------------------------
import os, platform, socket, subprocess, sys, time, re
from datetime import datetime as dt
from subprocess import Popen, PIPE

## Network scan function
def run_scanner(subnet, interface):

    try:
        ## Sets the range of ip address from subnet
        (ip, cidr) = subnet.split('/')
        cidr = int(cidr) 
        host_bits = 32 - cidr
        i = struct.unpack('>I', socket.inet_aton(ip))[0] # note the endianness
        start = (i >> host_bits) << host_bits # clear the host bits
        end = start | ((1 << host_bits) - 1)

        # excludes the first and last address in the subnet
        for i in range(start, end):
            print(socket.inet_ntoa(struct.pack('>I',i)))

        ## Validates if the OS is Windows or other
        ## and sets the appropriate commands
        oper = platform.system()
        if(oper == "Windows"):
            ping1 = "ping -n 1 "
            arping1 = "arping -n 1 -i " + interface
        else:
            ping1 = "ping -c 1 "
            arping1 = "arping -c 1 -i " + interface

        ## Scans the machines in the defined range
        print("Scanning in Progress")
        for ip in range(start,end):
            addr = net + '.' + str(ip)
            print("Testing ip " + addr)
            comm1 = ping1 + addr
            resp1 = os.popen(comm1)

            status = "DOWN"
            for line in resp1.readlines():
                if(line.upper().count("TTL")):
                    status = "UP"
                    #print(addr, "--> Live")
                    break

            if(status == "DOWN"):
                comm2 = arping1 + addr
                resp2 = os.popen(comm2)

                for line in resp2.readlines():
                    if(line.upper().count("RTT")):
                        status = "UP, NO ICMP"
                        #print(addr, "--> Live, NO ICMP")
                        break

            now = time.strftime('%Y-%m-%d %H:%M:%S')

            ## Get target MAC address
            Popen(["ping", "-c 1", addr], stdout = PIPE)
            pid = Popen(["arp", "-n", addr], stdout = PIPE)
            s = pid.communicate()[0]
            hasMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s.decode())
            if hasMac is not None:
                mac = hasMac.groups()[0]
            else:
                mac = 'None'

            hostname = socket.gethostbyaddr(addr)
            data = (addr,mac,hostname,now,status)

            if(status == "DOWN"):
                print(addr, "is unreachable")
            else:
                print(data)

    except KeyboardInterrupt:
        print("Execution interrupted: Ctrl+C")
        sys.exit()

## MAIN -------------------------------------
## Clear screen
subprocess.call('clear', shell=True)

if sys.argv == 2:
    interface = input("Enter the interface: ")

    ## Set the beginning datetime
    t1 = dt.now()

    subnets = open(sys.argv[1],"r")
    for subnet in subnets:
        ## Run the scanner
        run_scanner(subnet, interface)

    ## Set the ending datetime
    t2 = dt.now()

    ## Calculates the scan time and prints it
    total = t2 - t1
    print("Scanning completed in: ",total)

else:
    print(f'[-] Usage: {str(sys.argv[0])} <subnet_list>')
