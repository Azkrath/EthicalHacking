#!/usr/bin/python
#coding=utf-8
# Application that detects alive hosts using ICMP
# and does a port scan for every alive target
# by FM
# Python 3
# -------------------------------------
import os, platform, sys, time, re, ipaddress, threading, multiprocessing
from datetime import datetime as dt
from subprocess import Popen, PIPE
from multiprocessing.queues import Queue

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

## Set ips and interface in queue
def set_hosts(subnet, ping_cmd, arping_cmd):
    hosts = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
    for ip in hosts:
        queue.put((ip, ping_cmd, arping_cmd))

## Scan an ip address in order to check for host liveness
def ip_scan():
    while not queue.empty():
    
        ## Get args
        args = queue.get()
        ip = args[0]
        ping_cmd = args[1]
        arping_cmd = args[2]

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
            #print(data)
            live_hosts.put(data)


## Initialize threaded scanner with n threads
def initialize_scanner(threads, subnet, ping_cmd, arping_cmd):

    set_hosts(subnet, ping_cmd, arping_cmd)

    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=ip_scan)
        thread.Daemon = True
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

## MAIN -------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 2:
        ## Initialize Thread Queue
        queue = ImpQueue()

        ## Initialize Hosts Queue
        live_hosts = ImpQueue()

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

                ## Initialize threaded scanner with n threads
                initialize_scanner(256, subnet, ping_cmd, arping_cmd)

            ## Set the ending datetime
            t2 = dt.now()
            
            ## Calculates the scan time and prints it
            total = t2 - t1

            nbr_hosts_up = live_hosts.qsize()
            while not live_hosts.empty():
                host = live_hosts.get()
                print(host)

            print("Scanning completed in: ",total)
            print(str(nbr_hosts_up) + " hosts up.")

        except KeyboardInterrupt:
            print("Execution interrupted: Ctrl+C")
            sys.exit()

    else:
        print('[-] Usage: ' + sys.argv[0] + ' subnet_list.txt')
