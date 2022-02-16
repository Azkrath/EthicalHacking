#!/usr/bin/python
#coding=utf-8
# Application that detects alive hosts using ICMP and ARP
# by FM
# Python 3
# -------------------------------------
import os, platform, sys, time, re, ipaddress, threading, multiprocessing, scapy, socket
from datetime import datetime as dt
from subprocess import Popen, PIPE
from multiprocessing.queues import Queue
import scapy.all as scapy

# The following implementation of custom MyQueue to avoid NotImplementedError
# when calling queue.qsize() in MacOS X comes almost entirely from this github
# discussion: https://github.com/keras-team/autokeras/issues/368
# Necessary modification is made to make the code compatible with Python3.

class SharedCounter(object):
    """ A synchronized shared counter.
    The locking done by multiprocessing.Value ensures that only a single
    process or thread may read or write the in-memory ctypes object. However,
    in order to do n += 1, Python performs a read followed by a write, so a
    second process may read the old value before the new one is written by the
    first process. The solution is to use a multiprocessing.Lock to guarantee
    the atomicity of the modifications to Value.
    This class comes almost entirely from Eli Bendersky's blog:
    http://eli.thegreenplace.net/2012/01/04/shared-counter-with-pythons-multiprocessing/
    """

    def __init__(self, n=0):
        self.count = multiprocessing.Value('i', n)

    def increment(self, n=1):
        """ Increment the counter by n (default = 1) """
        with self.count.get_lock():
            self.count.value += n

    @property
    def value(self):
        """ Return the value of the counter """
        return self.count.value

class ImpQueue(Queue):
    """ A portable implementation of multiprocessing.Queue.
    Because of multithreading / multiprocessing semantics, Queue.qsize() may
    raise the NotImplementedError exception on Unix platforms like Mac OS X
    where sem_getvalue() is not implemented. This subclass addresses this
    problem by using a synchronized shared counter (initialized to zero) and
    increasing / decreasing its value every time the put() and get() methods
    are called, respectively. This not only prevents NotImplementedError from
    being raised, but also allows us to implement a reliable version of both
    qsize() and empty().
    Note the implementation of __getstate__ and __setstate__ which help to
    serialize MyQueue when it is passed between processes. If these functions
    are not defined, MyQueue cannot be serialized, which will lead to the error
    of "AttributeError: 'MyQueue' object has no attribute 'size'".
    See the answer provided here: https://stackoverflow.com/a/65513291/9723036
    
    For documentation of using __getstate__ and __setstate__ to serialize objects,
    refer to here: https://docs.python.org/3/library/pickle.html#pickling-class-instances
    """

    def __init__(self):
        super().__init__(ctx=multiprocessing.get_context())
        self.size = SharedCounter(0)

    def __getstate__(self):
        """Help to make MyQueue instance serializable.
        Note that we record the parent class state, which is the state of the
        actual queue, and the size of the queue, which is the state of MyQueue.
        self.size is a SharedCounter instance. It is itself serializable.
        """
        return {
            'parent_state': super().__getstate__(),
            'size': self.size,
        }

    def __setstate__(self, state):
        super().__setstate__(state['parent_state'])
        self.size = state['size']

    def put(self, *args, **kwargs):
        super().put(*args, **kwargs)
        self.size.increment(1)

    def get(self, *args, **kwargs):
        item = super().get(*args, **kwargs)
        self.size.increment(-1)
        return item

    def qsize(self):
        """ Reliable implementation of multiprocessing.Queue.qsize() """
        return self.size.value

    def empty(self):
        """ Reliable implementation of multiprocessing.Queue.empty() """
        return not self.qsize()

##
def get_hostname(ip):
    try:
        hostdata = socket.gethostbyaddr(ip)
        return hostdata[0]
    except socket.herror:
        return None

## Get MAC Address from IP
def get_macaddress(ip, oper):
    ## Get target MAC address
    if oper == "Windows":
        mac = scapy.getmacbyip(ip)
    else:    
        Popen(["ping", "-c 1", ip], stdout = PIPE)
        pid = Popen(["arp", "-n", ip], stdout = PIPE)
        s = pid.communicate()[0]
        hasMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s.decode())
        if hasMac is not None:
            mac = hasMac.groups()[0]
        else:
            mac = scapy.getmacbyip(ip)
    return mac

## Scan an ip address in order to check for host liveness
def ip_scan():
    while not queue.empty():
    
        ## Get args
        args = queue.get()

        ## Prepare args
        ip = args[0]
        oper = args[1]
        ping_cmd = args[2]
        arping_cmd = args[3]

        mac = None
        hostname = None
        target_os = "Unknown"
        status = "DOWN"

        com = ping_cmd + ip
        res = os.popen(com)
        for line in res.readlines():
            if line.upper().count("TTL"):
                ## Get TTL value from response
                ttl = 0
                pattern = re.compile(r'[t,T][t,T][l,L]=\d*')
                ttl_call = pattern.search(str(line))
                if ttl_call is not None:
                    ttl_group = ttl_call.group()
                    result_ttl = re.findall(r'\d+', ttl_group)
                    ttl = int(result_ttl[0])
                    if ttl > 32 and ttl < 70:
                        target_os = "Linux"
                    elif ttl > 119 and ttl < 200:
                        target_os = "Windows" 
                status = "UP"
                break

        if status == "DOWN":
            if oper == "Windows":
                com2 = arping_cmd + ip
                res2 = os.popen(com2)
                for line in res2.readlines():
                    if line.upper().count("RTT"):
                        status = "UP"
                        break
            else:
                ## Scapy implementation - not reliable with Windows
                ans, unans = scapy.arping(ip)
                if len(ans):
                    status = "UP"

        ## Get mac address from IP
        if status == "UP":
            mac = get_macaddress(ip, oper)
            
        ## Get hostname
        hostname = get_hostname(ip)

        ## Set data
        data = (ip,mac,hostname,target_os,status)
        if status == "UP":
            with thread_lock:
                live_hosts.put(data)

## Set ips and interface in queue
def set_hosts(subnet, oper, ping_cmd, arping_cmd):
    print(f"Setting hosts for subnet {subnet}")
    try:
        hosts = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
        
        for ip in hosts:
            ## Add target data to queue
            queue.put((ip, oper, ping_cmd, arping_cmd))
    except:
        print(f"Subnet {subnet} is invalid!")
        pass

## Initialize threaded scanner with n threads
def initialize_scanner(threads, subnet, oper, ping_cmd, arping_cmd):
    print(f"Initializing Scanning for subnet {subnet}")

    set_hosts(subnet, oper, ping_cmd, arping_cmd)

    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=ip_scan)
        thread.Daemon = True
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

## Set commands based on operating system
def set_commands(oper, timeout):
    if(oper == "Windows"):
        ping_cmd = f"ping -n 1 -w {timeout} "
        arping_cmd = f"arp-ping -n 1 "
    else:
        ## Ask for the interface for arping
        interface = input("Enter the interface: ")
        ping_cmd = f"ping -c 1 -t {timeout} "
        arping_cmd = f"arping -c 1 -i {interface} "

    return ping_cmd, arping_cmd

## MAIN -------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 2:
        ## Initialize Thread Queue
        queue = ImpQueue()

        ## Initialize Hosts Queue
        live_hosts = ImpQueue()

        ## Set a lock to prevent concurrency
        thread_lock = threading.Lock()

        try:

            ## Validates if the OS is Windows or other
            ## to set the appropriate commands
            oper = platform.system()
            
            ## Set scapy verbose mode to null
            scapy.conf.verb = 0

            ## Set commands based on host OS
            timeout = 4
            ping_cmd, arping_cmd = set_commands(oper, timeout)
            
            try:
                os.mkdir("Scans")
            except FileExistsError:
                pass
 
            # Muda de diretoria
            os.chdir("Scans")

            subnet = sys.argv[1]
            network = subnet.split("/",1)[0]
            with open(network+".txt", "w") as output:

                ## Scans the machines in the defined range
                print("Scanning in Progress")
                output.write("Scanning in Progress\n")

                thread_list = []
                threads = 1024

                ## Set the beginning datetime
                t1 = dt.now()

                ## Initialize threaded scanner with n threads
                initialize_scanner(threads, subnet, oper, ping_cmd, arping_cmd)
                
                ## Set the ending datetime
                t2 = dt.now()
                
                ## Calculates the scan time and prints it
                total = t2 - t1

                nbr_hosts_up = live_hosts.qsize()
                
                while not live_hosts.empty():
                    host = live_hosts.get()
                    print(host)
                    output.writelines(str(host)+"\n")

                print("Scanning completed in: ",total)
                print(str(nbr_hosts_up) + " hosts up.")

                output.write("Scanning completed in: " + str(total)+"\n")
                output.write(str(nbr_hosts_up) + " hosts up.\n")

            # Muda de diretoria
            os.chdir("../")

        except KeyboardInterrupt:
            print("Execution interrupted: Ctrl+C")
            sys.exit()

    else:
        print('[-] Usage: ' + sys.argv[0] + ' 192.168.1.0/24')
