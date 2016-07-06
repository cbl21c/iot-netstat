#!/usr/bin/python

#
# usage: iot-netstat.py [-h] -i IFNAME [-w WAIT] [--debug]
#
# IBM IOTF client which publishes network Rx/Tx packet count
#
# optional arguments:
#   -h, --help  show this help message and exit
#   -i IFNAME   interface name
#   -w WAIT     wait time between samples (default 10s)
#   --debug     print debug output
#


import os
import sys
import argparse
import subprocess
import time
import string
import ibmiotf.device


############################################################
#                                                          #
#  getPacketCount(osname, ifname)                          #
#                                                          #
#  Returns the number of received and transmitted packets  #
#  through ifname                                          #
#                                                          #
############################################################

def getPacketCount(osname, ifname):
    supportedOS = ['Darwin', 'FreeBSD', 'Linux']
    if osname not in supportedOS:
        return (None, None)

    if osname == 'Darwin' or osname == 'FreeBSD':
        # netstat -bI ifname
        cmd = ['netstat', '-bI', ifname]
        try:
            output = subprocess.check_output(cmd).decode('utf-8')
        except subprocess.CalledProcessError:
            return (None, None)

        for line in output.splitlines():
            if line.find('Link#') > 0:
                fields = line.split()
                rx = int(fields[4])
                tx = int(fields[7])

    if osname == 'Linux':
        # /sbin/ifconfig ifname
        cmd = ['/sbin/ifconfig', ifname]
        try:
            output = subprocess.check_output(cmd).decode('utf-8')
        except subprocess.CalledProcessError:
            return (None, None)

        for line in output.splitlines():
            wsline = string.replace(line, ':', ' ')
            fields = wsline.split()
            if line.find('RX packets') > 0:
                rx = int(fields[2])
            if line.find('TX packets') > 0:
                tx = int(fields[2])

    return (rx, tx)


################################################
#                                              #
#  getMACaddress(ifname)                       #
#                                              #
#  returns:                                    #
#    MAC address as string if ifname is valid  #
#    None otherwise                            #
#                                              #
################################################

def getMACaddress(ifname):
    cmd = ['/sbin/ifconfig', ifname]
    try:
        output = subprocess.check_output(cmd).decode('utf-8')
    except subprocess.CalledProcessError as e:
        return None

    # valid interface, but we also need to check that it is not loopback
    if output.find('LOOPBACK') > 0:
        return None

    # mac address starts 6 chars from the start of 'ether'
    # or 7 chars from the start of 'HWaddr' (Debian)
    # and is 17 chars in length
    if output.find('ether') > 0:
        macStart = output.find('ether') + 6
    else:
        macStart = output.find('HWaddr') + 7
    macEnd = macStart + 17
    macAddress = string.replace(output[macStart:macEnd], ':', '')

    return macAddress


################################
#                              #
#  argument parsing            #
#                              #
################################

# instantiate an argument parser
parser = argparse.ArgumentParser(description = "IBM IOTF client which publishes network Rx/Tx packet count")

# add optional arguments for wait time between samples, and debug flag
parser.add_argument("-i", dest="ifname", required=True, help="interface name")
parser.add_argument("-w", dest="wait", type=int, help="wait time between samples (default 10s)")
parser.add_argument("--debug", action="store_true", help="print debug output")


# parse the arguments
args = parser.parse_args()

# wait_time defaults to 10s if not specified
wait_time = 10
if args.wait:
    wait_time = args.wait


################################
#                              #
#  main()                      #
#                              #
################################

osname = os.uname()[0]

# mac address will form the client id
clientId = getMACaddress(args.ifname)
if clientId == None:
    print("Invalid interface %s" % args.ifname)
    sys.exit(-1)

# setup the iot configuration
# quickstart doesn't need any authentication
options = {
    'org': 'quickstart',
    'type': 'sysmon',
    'id': clientId,
    'auth-method': None,
    'auth-token': None
}

# override quickstart
options['org'] = 'nqi5cl'
options['type'] = 'MacBook'
options['auth-method'] = 'token'
options['auth-token'] = 'a8032e78b6df662f'


#
# initialise the device client
#
try:
    # connect to IOTF
    dev = ibmiotf.device.Client(options)
    dev.connect()
except ibmiotf.ConnectionException as e:
    print("Caught exception connecting device: %s" % str(e))
    sys.exit(-1)


#
# get the initial values
#
(prev_ipkts, prev_opkts) = getPacketCount(osname, args.ifname)
if prev_ipkts == None or prev_opkts == None:
    # cannot get initial values so we should just exit
    print("Could not get stats for %s" % args.ifname)
    sys.exit(-1)


#
# runloop
#
while True:
    try:
        time.sleep(wait_time)

        # get the next sample and calculate the delta
        # if we cannot get the sample, then just skip this sample period
        (ipkts, opkts) = getPacketCount(osname, args.ifname)
        if prev_ipkts == None or prev_opkts == None:
            continue

        delta_ipkts = ipkts - prev_ipkts
        delta_opkts = opkts - prev_opkts

        # timestamp in format YYYY-mm-DDTHH:MM:SSZ (use GMT)
        # example 2016-06-30T11:21:14Z
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        data = {
            'd': {
                'ipkts': delta_ipkts,
                 'opkts': delta_opkts
            },
            'ts': ts
        }

        prev_ipkts = ipkts
        prev_opkts = opkts

        if args.debug:
            sys.stdout.write('{\n')
            sys.stdout.write('  "d": {\n')
            sys.stdout.write('    "ipkts": ' + str(data['d']['ipkts']) + ',\n')
            sys.stdout.write('    "opkts": ' + str(data['d']['opkts']) + '\n')
            sys.stdout.write('  },\n')
            sys.stdout.write('  "ts": ' + ts + '\n')
            sys.stdout.write('}\n')

        success = dev.publishEvent("ethernet", "json", data)
        if not success:
            sys.stdout.write('publishEvent() failed\n')

    except KeyboardInterrupt:
        dev.disconnect()
        sys.exit(0)


