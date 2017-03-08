#!/usr/bin/python

import optparse
import socket
import sys
import time

icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')

def mean(data):
    """Return the sample arithmetic mean of data."""
    n = len(data)
    if n < 1:
        raise ValueError('mean requires at least one data point')
    return sum(data)/n # in Python 2 use sum(data)/float(n)

def _ss(data):
    """Return sum of square deviations of sequence data."""
    c = mean(data)
    ss = sum((x-c)**2 for x in data)
    return ss

def stdev(data):
    """Calculates the population standard deviation."""
    n = len(data)
    if n < 2:
        raise ValueError('variance requires at least two data points')
    ss = _ss(data)
    pvar = ss/n # the population variance
    return pvar**0.5

def process_round_trip_times(times):
    rtt = []
    all_timeout = True
    all_no_addr = True
    for i in range(len(times)):
        if times[i] == -1:
            all_timeout &= True
        elif times[i] == "*":
            all_no_addr &= True
        else:
            rtt.append(times[i])
            all_timeout &= False
            all_no_addr &= False

    return rtt, all_timeout, all_no_addr

def create_sockets(ttl, timeout):
    """
    Sets up sockets necessary for the traceroute.  We need a receiving
    socket and a sending socket. 
    """
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)    
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
    
    """
	Set socket options and timeout value for the recv socket
	"""
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    recv_socket.settimeout(timeout)

    return recv_socket, send_socket

def main(dest_name, port, max_hops, timeout):
    dest_addr = socket.gethostbyname(dest_name)

    print "Tracing route to %s [%s] over a maximum of %d hops: " % (dest_name, dest_addr, max_hops)
    print "Running on port %s with a timeout of %d seconds: " 
    print "TTL \t \t \t \t \t \t \t Avg \t\t Std "
    ttl = 1

    while True:

        tracer_addr = None
        tracer_name = None

        round_trip_times = []

        for i in range(3):

            recv_socket, send_socket = create_sockets(ttl, timeout)
            recv_socket.bind(("", port))
            send_socket.sendto("", (dest_name, port))

            """
            Record the current time
            """
            start_time = time.time()

            curr_addr = None
            curr_name = None
            try:
                # socket.recvfrom() gives back (data, address), but we
                # only care about the latter.
                _, curr_addr = recv_socket.recvfrom(512)
                curr_addr = curr_addr[0]  # address is given as tuple

                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr

                """
                Compute the round trip time
                """
                round_trip = (time.time() - start_time) * 1000

            except socket.timeout:
                """
                Handle time out 
                """
                round_trip_times.append(-1)

                continue
            except socket.error:
                pass
            finally:
                send_socket.close()
                recv_socket.close()

            if curr_addr is not None:
                tracer_addr = curr_addr
                tracer_name = curr_name

                round_trip_times.append(round_trip)
            else:
                round_trip_times.append("*")

        rtt, all_timeout, all_no_addr = process_round_trip_times(round_trip_times)
        
        #process data for formatting

        if len(rtt) > 0:
            avg = mean(rtt)
            avg = "{:.3f}".format(avg) + " ms"
        else:
            avg = "-\t"

        if len(rtt) >= 2:
            std = stdev(rtt)
            std = "{:.3f}".format(std) + " ms"
        else:
            std = "-\t"

        if round_trip_times[0] != "*" and round_trip_times[0] != -1:
            time0 = "{:.3f}".format(round_trip_times[0]) + " ms"
        else:
            time0 = "*\t"

        if round_trip_times[1] != "*" and round_trip_times[1] != -1:
            time1 = "{:.3f}".format(round_trip_times[1]) + " ms"
        else:
            time1 = "*\t"

        if round_trip_times[2] != "*" and round_trip_times[2] != -1:
            time2 = "{:.3f}".format(round_trip_times[2]) + " ms"
        else: 
            time2 = "*\t"

        if all_timeout:
            tracer_name = "Request Timed Out"
            tracer_addr = ""
        elif all_no_addr:
            tracer_name = ""
            tracer_addr = ""

        print "%d\t %s \t %s \t %s \t %s \t %s \t %s (%s)" % (ttl, time0, time1, time2, avg, std, tracer_name, tracer_addr)

        ttl += 1
        if tracer_addr == dest_addr or ttl > max_hops:
            break
    
    print "Trace Complete"

    return 0

if __name__ == "__main__":
    parser = optparse.OptionParser(usage="%prog [options] hostname")
    parser.add_option("-p", "--port", dest="port",
                      help="Port to use for socket connection [default: %default]",
                      default=33434, metavar="PORT")
    parser.add_option("-m", "--max-hops", dest="max_hops",
                      help="Max hops before giving up [default: %default]",
                      default=30, metavar="MAXHOPS")

    parser.add_option("-t", "--timeout", dest="timeout",
                      help="Timeout for tracer receive [default: %default]",
                      default = 5, metavar="TIMEOUT")

    options, args = parser.parse_args()
    if len(args) != 1:
        parser.error("No destination host")
    else:
        dest_name = args[0]

    """
	Modify the following to include an argument to store the timeout value
    """
	#Change the following line
    print "Dest name: ", dest_name
    sys.exit(main(dest_name=dest_name,
                  port=int(options.port),
                  max_hops=int(options.max_hops),
                  timeout=float(options.timeout)))
