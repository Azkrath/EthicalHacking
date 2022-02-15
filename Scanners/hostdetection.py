#!/usr/bin/python
#coding=utf-8
# Application that detects alive hosts using ICMP and ARP
# by FM
# Python 3
# -------------------------------------
import os, platform, socket, subprocess, sys, time, threading, re, requests
import mysql.connector as mysql
from datetime import datetime as dt
from multiprocessing import Queue
from subprocess import Popen, PIPE
from concurrent.futures import ThreadPoolExecutor, as_completed

## Make database operation
def doOperation(operation,data=None):

    ## Define prepared statements to be used  --------------------------------------------------------------

    ### SELECT ###
    selectAll = """ SELECT * FROM addresses WHERE status = 'UP' OR status = 'UP, NO ICMP' """
    selectPorts = """ SELECT port FROM ports WHERE ipAddrV4 = %s AND status = 'OPEN' """
    selectRecord = """ SELECT COUNT(*) FROM addresses WHERE ipAddrV4 = %s """
    selectPortRecord = """ SELECT COUNT(*) FROM ports WHERE ipAddrV4 = %s AND port = %s """

    ### INSERT ###
    insertRecord = """ INSERT INTO addresses (ipAddrV4,macAddr,timestamp,status) VALUES (%s,%s,%s,%s) """
    insertPortRecord = """ INSERT INTO ports (ipAddrV4, port, status) VALUES (%s, %s, %s) """

    ### UPDATE ###
    updateRecord = """ UPDATE addresses set macAddr = %s, timestamp = %s ,status = %s  WHERE ipAddrV4 = %s """
    updatePortRecord = """ UPDATE ports set status = %s WHERE ipAddrV4 = %s AND port = %s """

    ### DELETE ###
    deleteRecords = """ DELETE FROM addresses where 1=1 """

    ## -----------------------------------------------------------------------------------------------------

    ## Connect to database
    db = mysql.connect(
            host='127.0.0.1',
            port='3306',
            user='root',
            passwd='dbms',
            database='portscan'
            )
    ## Get cursor
    mycursor = db.cursor(prepared=True)

    if(operation == "selectAll"):
        ## Execute operation
        mycursor.execute(selectAll)
        resultSet = mycursor.fetchall()
        for result in resultSet:
            print("IP: {}, MAC: {}, TIMESTAMP: {}, STATUS: {}".format(result[0].decode(), result[1].decode(), result[2].decode(), result[3].decode()))
            IP = str(result[0].decode())
            mycursor.execute(selectPorts,[IP])
            portResult = mycursor.fetchall()
            open_ports = []
            for port in portResult:
                open_ports.append(port[0])
            print("Open ports for the host {} are".format(IP), open_ports)

    if (operation == "insertRecord"):
        IP = str(data[0])
        ## Execute operation
        mycursor.execute(selectRecord, [IP])
        resultSet = mycursor.fetchall()
        if (int(resultSet[0][0]) > 0):
            updData = (data[1], data[2], data[3], data[0])
            mycursor.execute(updateRecord,updData)
        else:
            mycursor.execute(insertRecord,data)

        ## Commit database changes
        db.commit()

    if (operation == "insertPortRecord"):
        ## Execute operation
        mycursor.execute(selectPortRecord,[data[0],data[1]])
        resultSet = mycursor.fetchall()
        if (int(resultSet[0][0] > 0)):
            updData = (data[2],data[0],data[1])
            mycursor.execute(updatePortRecord, updData)
        else:
            mycursor.execute(insertPortRecord,data)

        ## Commit database changes
        db.commit()

    db.close()

## Set Ports in queue function function
def set_ports(host):

    ## Define the maximum ports to be scanned 
    max_port = 1024

    ## Set the default socket timout
    socket.setdefaulttimeout(5)

    for port in range(1, max_port+1):
        queue.put((host,port))

## Host port scan function
def portscan(host,port):

    ## Do a port scan on the host via socket connection to that port
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        result = sock.connect_ex((host,port))
        sock.close()

        if result == 0:
            return True
        else:
            return False

    except socket.error:
        print("Couldn't connect to host. Exiting")
        sys.exit()

    except socket.gaierror:
        print("Host could not be resolved. Exiting")
        sys.exit()
    except:
        return False

## Thread Worker function
def worker():

    while not queue.empty():
        data = queue.get()
        ## Save port state to database
        if portscan(data[0], data[1]):
            ## Use db lock to prevent concurrent access to mysql
            with thread_lock:
                doOperation("insertPortRecord",(data[0],data[1],"OPEN"))
                #print("Port {} opened on host {}".format(data[1],data[0]))
        else:
            ## Use db lock to prevent concurrent access to mysql
            with thread_lock:
                doOperation("insertPortRecord",(data[0],data[1],"CLOSED"))
                #print("Port {} closed on host {}".format(data[1],data[0]))

## Initialize threaded scanner with n threads
def initialize_scanner(threads,host):

    set_ports(host)

    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=worker)
        thread.Daemon = True
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    #print("Open ports for host " + host +  " are: ", open_ports)

## Network scan function
def run_scanner():

    ## Clear screen
    subprocess.call('clear', shell=True)

    try:

        ## Asks for network address to scan
        net = '.'.join(input("Enter network address: ").split(".")[:-1])

        ## Asks for range of machines
        st1 = int(input("Enter the starting number: "))
        en1 = int(input("Enter the last number: ")) + 1
        oper = platform.system()

        ## Validates if the OS is Windows or other
        if(oper == "Windows"):
            ping1 = "ping -n 1 "
            arping1 = "arping -n 1 "
        else:
            ping1 = "ping -c 1 "
            arping1 = "arping -c 1 "

        ## Set the beginning datetime
        t1 = dt.now()

        ## Scans the machines in the defined range
        print("Scanning in Progress")
        for ip in range(st1,en1):
            addr = net + '.' + str(ip)
            print("Testing ip " + addr)
            comm1 = ping1 + addr
            resp1 = os.popen(comm1)

            status = "DOWN"
            for line in resp1.readlines():
                if(line.upper().count("TTL")):
                    status = "UP"
                    print(addr, "--> Live")
                    break

            if(status == "DOWN"):
                comm2 = arping1 + addr
                resp2 = os.popen(comm2)

                for line in resp2.readlines():
                    if(line.upper().count("RTT")):
                        status = "UP, NO ICMP"
                        print(addr, "--> Live, NO ICMP")
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

            data = (addr,mac,now,status)
            doOperation("insertRecord",data)

            if(status == "DOWN"):
                print(addr, "is unreachable")
            else:
                ## Initialize threaded port scan with n threads
                initialize_scanner(250,addr)

        ## Set the ending datetime
        t2 = dt.now()

        ## Calculates the scan time and prints it
        total = t2 - t1
        print("Scanning completed in: ",total)

        print("Hosts scanned: ")
        doOperation("selectAll")

    except KeyboardInterrupt:
        print("Execution interrupted: Ctrl+C")
        sys.exit()

## MAIN -------------------------------------
## Initialize Thread Queue
queue = Queue()

## Set a lock to prevent concurrency
thread_lock = threading.Lock()

## Run the scanner
run_scanner()

