#!/usr/bin/env python

# Copyright 2014 Roland Knall <rknall [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

"""
This is a generic example, which produces pcap packages every n seconds, and
is configurable via extcap options.

@note
{
To use this script on Windows, please generate an extcap_example.bat inside
the extcap folder, with the following content:

-------
@echo off
<Path to python interpreter> <Path to script file> %*
-------

Windows is not able to execute Python scripts directly, which also goes for all
other script-based formates beside VBScript
}

"""

from __future__ import print_function

import os
import sys
import signal
import re
import argparse
import time
import struct
import binascii
import usbmon
from threading import Thread

from beagle_py import *

print(sys.argv, file=sys.stderr)

log_me = open("/Users/tannewt/beaglecaplog.txt", "a")

#==========================================================================
# MAIN PROGRAM
#==========================================================================


ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3
ERROR_DELAY          = 4

CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

CTRL_ARG_MESSAGE     = 0
CTRL_ARG_DELAY       = 1
CTRL_ARG_VERIFY      = 2
CTRL_ARG_BUTTON      = 3
CTRL_ARG_HELP        = 4
CTRL_ARG_RESTORE     = 5
CTRL_ARG_LOGGER      = 6
CTRL_ARG_NONE        = 255

initialized = False
message = ''
delay = 0.0
verify = False
button = False
button_disabled = False

samplerate_khz = 0

def TIMESTAMP_TO_NS (stamp, samplerate_khz):
    return int((stamp * 1000) // (samplerate_khz // 1000))

"""
This code has been taken from http://stackoverflow.com/questions/5943249/python-argparse-and-controlling-overriding-the-exit-status-code - originally developed by Rob Cowie http://stackoverflow.com/users/46690/rob-cowie
"""
class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        """Given a name, get the Action instance registered with this parser.
        If only it were made available in the ArgumentError object. It is
        passed as it's first arg...
        """
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)

#### EXTCAP FUNCTIONALITY

"""@brief Extcap configuration
This method prints the extcap configuration, which will be picked up by the
interface in Wireshark to present a interface specific configuration for
this extcap plugin
"""
def extcap_config(interface, option):
    args = []
    values = []

    # args.append ( (0, '--delay', 'Time delay', 'Time delay between packages', 'integer', '{range=1,15}{default=5}') )
    # args.append ( (1, '--message', 'Message', 'Package message content', 'string', '{required=false}{placeholder=Please enter a message here ...}') )
    # args.append ( (2, '--verify', 'Verify', 'Verify package content', 'boolflag', '{default=yes}') )
    # args.append ( (3, '--fake_ip', 'Fake IP Address', 'Use this ip address as sender', 'string', '{save=false}{validation=\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b}'))
    # args.append ( (4, '--ltest', 'Long Test', 'Long Test Value', 'long', '{default=123123123123123123}{group=Numeric Values}'))
    # args.append ( (5, '--d1test', 'Double 1 Test', 'Long Test Value', 'double', '{default=123.456}{group=Numeric Values}'))
    # args.append ( (6, '--d2test', 'Double 2 Test', 'Long Test Value', 'double', '{default= 123,456}{group=Numeric Values}'))
    # args.append ( (7, '--ts', 'Start Time', 'Capture start time', 'timestamp', '{group=Time / Log}') )
    args.append ( (8, '--logfile', 'Log File Test', 'The Log File Test', 'fileselect', '{group=Time / Log}') )


def extcap_version():
    print ("extcap {version=1.0}{help=http://www.wireshark.org}{display=Example extcap interface}")

def extcap_interfaces():
    print ("extcap {version=1.0}{help=http://www.wireshark.org}{display=Example extcap interface}")

    # Find all the attached devices
    (num, ports, unique_ids) = bg_find_devices_ext(16, 16)

    # Print the information on each device
    for i in range(num):
        port      = ports[i]
        unique_id = unique_ids[i]

        # Determine if the device is in-use
        inuse = "(avail)"
        if (port & BG_PORT_NOT_FREE):
            inuse = "(in-use)"
            port  = port & ~BG_PORT_NOT_FREE

        # Display device port number, in-use status, and serial number
        print ("interface {value=beagle%d}{display=Beagle %d %s (%04d-%06d)}"%
                      (port, port, inuse, unique_id // 1000000, unique_id % 1000000))


    print ("control {number=%d}{type=string}{display=Message}{tooltip=Package message content. Must start with a capital letter.}{placeholder=Enter package message content here ...}{validation=^[A-Z]+}" % CTRL_ARG_MESSAGE)
    print ("control {number=%d}{type=selector}{display=Time delay}{tooltip=Time delay between packages}" % CTRL_ARG_DELAY)
    print ("control {number=%d}{type=boolean}{display=Verify}{default=true}{tooltip=Verify package content}" % CTRL_ARG_VERIFY)
    print ("control {number=%d}{type=button}{display=Turn on}{tooltip=Turn on or off}" % CTRL_ARG_BUTTON)
    print ("control {number=%d}{type=button}{role=help}{display=Help}{tooltip=Show help}" % CTRL_ARG_HELP)
    print ("control {number=%d}{type=button}{role=restore}{display=Restore}{tooltip=Restore default values}" % CTRL_ARG_RESTORE)
    print ("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}" % CTRL_ARG_LOGGER)
    print ("value {control=%d}{value=1}{display=1}" % CTRL_ARG_DELAY)
    print ("value {control=%d}{value=2}{display=2}" % CTRL_ARG_DELAY)
    print ("value {control=%d}{value=3}{display=3}" % CTRL_ARG_DELAY)
    print ("value {control=%d}{value=4}{display=4}" % CTRL_ARG_DELAY)
    print ("value {control=%d}{value=5}{display=5}{default=true}" % CTRL_ARG_DELAY)
    print ("value {control=%d}{value=60}{display=60}" % CTRL_ARG_DELAY)


def extcap_dlts(interface):
    if ( interface == '1' ):
        print ("dlt {number=147}{name=USER0}{display=Demo Implementation for Extcap}")
    elif ( interface == '2' ):
        print ("dlt {number=148}{name=USER1}{display=Demo Implementation for Extcap}")

def validate_capture_filter(capture_filter):
    if capture_filter != "filter" and capture_filter != "valid":
        print("Illegal capture filter")

"""

### FAKE DATA GENERATOR

Extcap capture routine
 This routine simulates a capture by any kind of user defined device. The parameters
 are user specified and must be handled by the extcap.

 The data captured inside this routine is fake, so change this routine to present
 your own input data, or call your own capture program via Popen for example. See

 for more details.

"""
def unsigned(n):
    return int(n) & 0xFFFFFFFF

def pcap_fake_header():

    header = bytearray()
    header += struct.pack('<L', int ('a1b2c3d4', 16 ))
    header += struct.pack('<H', unsigned(2) ) # Pcap Major Version
    header += struct.pack('<H', unsigned(4) ) # Pcap Minor Version
    header += struct.pack('<I', int(0)) # Timezone
    header += struct.pack('<I', int(0)) # Accurancy of timestamps
    header += struct.pack('<L', int ('0000ffff', 16 )) # Max Length of capture frame
    header += struct.pack('<L', unsigned(220)) # USB
    return header

def control_read(fn):
    try:
        header = fn.read(6)
        sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
        if length > 2:
            payload = fn.read(length - 2)
        else:
            payload = ''
        return arg, typ, payload
    except:
        return None, None, None

def control_read_thread(control_in, fn_out):
    global initialized, message, delay, verify, button, button_disabled
    with open(control_in, 'rb', 0 ) as fn:
        arg = 0
        while arg != None:
            arg, typ, payload = control_read(fn)
            log = ''
            if typ == CTRL_CMD_INITIALIZED:
                initialized = True
            elif arg == CTRL_ARG_MESSAGE:
                message = payload
                log = "Message = " + payload
            elif arg == CTRL_ARG_DELAY:
                delay = float(payload)
                log = "Time delay = " + payload
            elif arg == CTRL_ARG_VERIFY:
                # Only read this after initialized
                if initialized:
                    verify = (payload[0] != '\0')
                    log = "Verify = " + str(verify)
                    control_write(fn_out, CTRL_ARG_NONE, CTRL_CMD_STATUSBAR, "Verify changed")
            elif arg == CTRL_ARG_BUTTON:
                control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_DISABLE, "")
                button_disabled = True
                if button == True:
                    control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_SET, "Turn on")
                    button = False
                    log = "Button turned off"
                else:
                    control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_SET, "Turn off")
                    button = True
                    log = "Button turned on"

            if len(log) > 0:
                control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, log + "\n")

def control_write(fn, arg, typ, payload):
    packet = bytearray()
    packet += struct.pack('>sBHBB', b'T', 0, len(payload) + 2, arg, typ)
    if sys.version_info[0] >= 3 and isinstance(payload, str):
        packet += payload.encode('utf-8')
    else:
        packet += payload
    fn.write(packet)

def control_write_defaults(fn_out):
    global initialized, message, delay, verify

    while not initialized:
        time.sleep(.1)  # Wait for initial control values

    # Write startup configuration to Toolbar controls
    control_write(fn_out, CTRL_ARG_MESSAGE, CTRL_CMD_SET, message)
    control_write(fn_out, CTRL_ARG_DELAY, CTRL_CMD_SET, str(int(delay)))
    control_write(fn_out, CTRL_ARG_VERIFY, CTRL_CMD_SET, struct.pack('B', verify))

    for i in range(1,16):
        item = bytearray()
        item += str(i) + struct.pack('B', 0) + str(i) + " sec"
        control_write(fn_out, CTRL_ARG_DELAY, CTRL_CMD_ADD, item)

    control_write(fn_out, CTRL_ARG_DELAY, CTRL_CMD_REMOVE, str(60))

def output_urb(timestamp, urb, outstream):
    raw_urb = urb.encode()

    pcap = bytearray()

    caplength = len(raw_urb)

    # timestamp seconds, timestamp nanoseconds, length captured, length in frame
    pcap += struct.pack('<LLLL', unsigned(timestamp / 1000000), unsigned(timestamp % 1000000), unsigned(caplength), unsigned(caplength))

    pcap += raw_urb

    outstream.write(pcap)

def extcap_capture(interface, fifo, control_in, control_out, in_delay, in_verify, in_message, remote, fake_ip):
    global message, delay, verify, button_disabled

    print("hello", interface, type(interface))
    fn_out = None
    timing_size = bg_bit_timing_size(BG_PROTOCOL_USB, 1024)
    pid        = 0
    last_pid   = 0

    with open(fifo, 'wb', 0 ) as fh:
        fh.write (pcap_fake_header())

        if control_out != None:
            fn_out = open(control_out, 'wb', 0)
            control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_SET, "Log started at " + time.strftime("%c") + "\n")

        if control_in != None:
            # Start reading thread
            thread = Thread(target = control_read_thread, args = (control_in, fn_out))
            thread.start()

        if fn_out != None:
            control_write_defaults(fn_out)

        beagle = bg_open(int(interface))

        global samplerate_khz
        samplerate_khz = bg_samplerate(beagle, 0)
        bg_timeout(beagle, 10)

        enable_result = bg_enable(beagle, BG_PROTOCOL_USB)
        if (enable_result != BG_OK):
            print("device error:", enable_result)
            return

        # Output the header...
        sys.stdout.flush()

        # Allocate the arrays to be passed into the read function
        packet = array_u08(1024)
        timing = array_u32(timing_size)

        urb = usbmon.Packet()
        data = bytearray()
        counter = 0

        # ...then start decoding packets
        while True:
            if fn_out != None:
                log = "Received packet #" + str(counter) + "\n"
                control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, log)
                counter = counter + 1

                if button_disabled == True:
                    control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_ENABLE, "")
                    control_write(fn_out, CTRL_ARG_NONE, CTRL_CMD_INFORMATION, "Turn action finished.")
                    button_disabled = False

            last_pid = pid
            length, status, events, time_sop, time_duration, time_dataoffset, packet, timing = bg_usb2_read_bit_timing (beagle, packet, timing)


            time_sop_ns = TIMESTAMP_TO_NS(time_sop, samplerate_khz)

            # Check for invalid packet or Beagle error
            if (length < 0):
                break

            if (length > 0):
                pid = packet[0]
            else:
                pid = 0

            if pid == BG_USB_PID_SOF:
                continue

            #print(map(hex, packet[:length]))

            if pid == BG_USB_PID_SETUP:
                #print("setup")
                urb.event_type = ord('S')
                urb.device_address = packet[1]
                urb.endpoint_number = packet[2]
                urb.transfer_type = 2 # control
                urb.setup_flag = 0
                setup_complete = False
            elif pid == BG_USB_PID_IN:
                #print("in")
                if urb.setup_flag != 0:
                    if not urb.event_type:
                        urb.event_type = ord('S')
                    urb.transfer_type = 3 # bulk
                    urb.device_address = packet[1]
                    urb.endpoint_number = packet[2]
                elif urb.union.bmRequestType == 0:
                    setup_complete = True
            elif pid == BG_USB_PID_OUT:
                #print("out")
                if urb.setup_flag != 0:
                    urb.event_type = ord('S')
                    urb.transfer_type = 3 # bulk
                    urb.device_address = packet[1]
                    urb.endpoint_number = packet[2]
                elif urb.union.bmRequestType != 0:
                    setup_complete = True
            elif pid in (BG_USB_PID_DATA0, BG_USB_PID_DATA1, BG_USB_PID_DATA2):
                #print("data")
                packet_data = bytearray()
                packet_data.extend(packet[1:length])
                if urb.setup_flag == 0 and len(packet_data) == 10 and urb.event_type == ord('S'):
                    setup_data = usbmon.SetupData()
                    setup_data.decode(packet_data[:9])
                    urb.union = setup_data
                else:
                    data.extend(packet_data[:-2])
            elif pid == BG_USB_PID_ACK:
                #print("ack")
                urb.data = bytes(data)
                total_microseconds = time_sop_ns // 1000
                seconds = total_microseconds // 1000000
                microseconds = total_microseconds % 1000000
                urb.ts_sec = seconds
                urb.ts_usec = microseconds
                if urb.setup_flag == 0:
                    if urb.event_type == ord('S'):
                        output_urb(total_microseconds, urb, fh)
                        urb.event_type = ord('C')
                    elif not setup_complete:
                        pass
                    else:
                        output_urb(total_microseconds, urb, fh)
                        data = bytearray()
                        urb = usbmon.Packet()
                # MSC packets start with USB so this is a crude way to group them like Linux does.
                elif urb.data[:3] == b"USB":
                    output_urb(total_microseconds, urb, fh)
                    data = bytearray()
                    urb.event_type = ord('C')
                else:
                    output_urb(total_microseconds, urb, fh)
                    data = bytearray()
                    urb = usbmon.Packet()
            elif pid == BG_USB_PID_STALL:
                #print("stall")
                data = bytearray()
                urb = usbmon.Packet()
            elif pid ==  BG_USB_PID_NAK:
                #print("nack")
                # Data is retransmitted so drop it.
                data = bytearray()
            else:
                #print("unsupported", pid)
                #raise RuntimeError("unsupported packet type {}".format(packet_type))
                pass

        # Stop the capture
        bg_disable(beagle)

        bg_close(beagle)

    print("finished")

    thread.join()
    if fn_out != None:
        fn_out.close()

def extcap_close_fifo(fifo):
    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0 )
    fh.close()

####

def usage():
    print ( "Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0] )

if __name__ == '__main__':
    interface = ""
    option = ""

    # Capture options
    delay = 0
    message = ""
    fake_ip = ""
    ts = 0

    print(sys.argv, file=sys.stderr)
    log_me.write(str(sys.argv) + "\n")

    parser = ArgumentParser(
            prog="Extcap Example",
            description="Extcap example program for python"
            )

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # Interface Arguments
    parser.add_argument("--verify", help="Demonstrates a verification bool flag", action="store_true" )
    parser.add_argument("--delay", help="Demonstrates an integer variable", type=int, default=0, choices=[0, 1, 2, 3, 4, 5, 6] )
    parser.add_argument("--remote", help="Demonstrates a selector choice", default="if1", choices=["if1", "if2", "if3", "if4"] )
    parser.add_argument("--message", help="Demonstrates string variable", nargs='?', default="" )
    parser.add_argument("--fake_ip", help="Add a fake sender IP adress", nargs='?', default="127.0.0.1" )
    parser.add_argument("--ts", help="Capture start time", action="store_true" )


    log_me.write("parse\n")
    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print( "%s: %s" % ( exc.argument.dest, exc.message ), file=sys.stderr)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if (arg == "--fifo" or arg == "--extcap-fifo") :
                fifo_found = 1
            elif ( fifo_found == 1 ):
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    log_me.write("parse done\n")
    if ( len(sys.argv) <= 1 ):
        parser.exit("No arguments given!")

    if ( args.extcap_version and not args.extcap_interfaces ):
        extcap_version()
        sys.exit(0)

    if ( args.extcap_interfaces == False and args.extcap_interface == None ):
        parser.exit("An interface must be provided or the selection must be displayed")
    if ( args.extcap_capture_filter and not args.capture ):
        validate_capture_filter(args.extcap_capture_filter)
        sys.exit(0)

    if ( args.extcap_interfaces == True or args.extcap_interface == None ):
        extcap_interfaces()
        sys.exit(0)

    log_me.write("interfaces\n")
    if ( len(unknown) > 1 ):
        print("Extcap Example %d unknown arguments given" % len(unknown) )

    m = re.match ( 'beagle(\d+)', args.extcap_interface )
    if not m:
        sys.exit(ERROR_INTERFACE)
    interface = m.group(1)

    log_me.write("interfaces\n")
    message = args.message
    if ( args.message == None or len(args.message) == 0 ):
        message = "Extcap Test"

    fake_ip = args.fake_ip
    if ( args.fake_ip == None or len(args.fake_ip) < 7 or len(args.fake_ip.split('.')) != 4 ):
        fake_ip = "127.0.0.1"

    ts = args.ts

    if ( args.extcap_reload_option and len(args.extcap_reload_option) > 0 ):
        option = args.extcap_reload_option

    log_me.write("blah\n")
    if args.extcap_config:
        extcap_config(interface, option)
    elif args.extcap_dlts:
        extcap_dlts(interface)
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)
        # The following code demonstrates error management with extcap
        if args.delay > 5:
            print("Value for delay [%d] too high" % args.delay, file=sys.stderr)
            extcap_close_fifo(args.fifo)
            sys.exit(ERROR_DELAY)

        try:
            extcap_capture(interface, args.fifo, args.extcap_control_in, args.extcap_control_out, args.delay, args.verify, message, args.remote, fake_ip)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(e, file=sys.stderr)
            sys.exit(ERROR_USAGE)
    else:
        usage()
        sys.exit(ERROR_USAGE)
