#!/usr/bin/env python
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from random import randint
from select import select
import socket
import ssl
import subprocess
import sys
import traceback

import pytun

__author__ = "Zhao Xiang Lim"
__copyright__ = "Copyright 2017 Zhao Xiang."
__license__ = "Apache License 2.0"

DEBUG = False
AUTOSSL_PATH = "/tmp/L2pivot"

def print_info(buf):
    print("[*] {0}".format(buf))

def print_good(buf):
    print("[+] {0}".format(buf))

def print_bad(buf):
    print("[-] {0}".format(buf))

def print_error(buf):
    print("[!] {0}".format(buf))

def print_debug(buf):
    if DEBUG:
        print("[DEBUG] {0}".format(buf))


class TapInterface():
    """Class for TAP interface management."""

    def __init__(self):
        """
        TapInterface init function.

        self.dev is the name of the network interface.
        self.tap is the TAP interface.
        """
        self.dev = "pivot{0}".format(randint(0, 100000))
        self.tap = self.__get_tap()

    def __get_tap(self):
        """Creates a TAP interface with the given name (self.dev) and returns it."""
        return pytun.TunTapDevice(flags=pytun.IFF_TAP|pytun.IFF_NO_PI, name=self.dev)

    def tstart(self):
        """Start the TAP interface."""
        self.tap.up()
        print_good("{0}: TAP Interface opened.".format(self.dev))

    def tstop(self):
        """Stop the TAP interface."""
        self.tap.down()
        self.tap.close()
        print_bad("{0}: TAP Interface closed.".format(self.dev))

    def tread(self):
        """Read data from the TAP interface."""
        buf = self.tap.read(65535)
        print_debug("{0}: Read {1} bytes from TAP.".format(self.dev, len(buf)))
        return buf

    def twrite(self, buf):
        """Write data to the TAP interface."""
        self.tap.write(buf)
        print_debug("{0}: Written {1} bytes to TAP.".format(self.dev, len(buf)))

    def dhcp(self):
        """
        Request for an IP Address for the TAP interface using dhclient.

        This is the limitation of this program, in that it requires a
        system that has dhclient present.

        This will only work if the pivoted network supports DHCP.
        """
        try:
            print_debug("{0}: Issuing DHCP request.".format(self.dev))
            subprocess.Popen(["dhclient", self.dev])
            return True
        except Exception as e:
            print_error(e)
            traceback.print_exc()
            return None


class Client():
    """Class for client callback management."""

    def __init__(self, sock, addr, port):
        """
        Client init function.

        Args:
            sock (socket):  The socket object containing the client connection.
            addr (str):     The IPv4 Address of the client connection.
            port (int):     The port number of the client connection.
        """
        self.tap = TapInterface()
        self.sock = sock
        self.addr = addr
        self.port = port
        self.tap.tstart()
        print_good("{0} ({1}/tcp): Opened socket.".format(self.addr, self.port))

    def disconnect(self):
        """Disconnects a client from the server."""
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                print_bad("{0} ({1}/tcp): Closed socket.".format(self.addr, self.port))
                self.tap.tstop()
            return True
        except socket.error:
            # Usually happens if client force-terminate the callback program.
            print_bad("{0} ({1}/tcp): Socket disconnected.".format(self.addr, self.port))
            self.tap.tstop()
            return True
        except Exception as e:
            print_error(e)
            traceback.print_exc()
            return None

    def csend(self, buf, mtu):
        """
        Send data to the client.

        Args:
            buf:        Data to send to the client.
            mtu (int):  The maximum transmission unit.
        """
        try:
            send_len = 0

            # Send the size of the buffer (In network byte order)
            # to the client first.
            buf_size = len(buf)
            self.sock.sendall(str(socket.htons(buf_size)))

            print_debug("{0} ({1}/tcp): Sending {2} bytes...".format(self.addr, self.port, buf_size))

            # Split the buffer into chunks of size matching the MTU.
            chunks = [buf[i:i+mtu] for i in range(0, buf_size, mtu)]

            for chunk in chunks:
                self.sock.sendall(chunk)
                send_len = send_len + len(chunk)
                print_debug("{0} ({1}/tcp): Sending {2}/{3} bytes".format(self.addr, self.port, send_len, buf_size))

            assert buf_size == send_len
            print_debug("{0} ({1}/tcp): Sent {2} bytes total".format(self.addr, self.port, buf_size))
            return True
        except Exception as e:
            print_error(e)
            traceback.print_exc()
            return None

    def crecv(self, mtu):
        """
        Receive data from the client.

        Args:
            mtu (int):  The maximum transmission unit.

        Returns:
            buf:        The data sent by the client.
        """
        try:
            buf_fragment = []
            read_len, read_size, buf_left = 0, 0, 0

            # Receive the size of the buffer (In network byte order)
            # from the client first.
            buf_size = socket.ntohs(int(self.sock.recv(5)))
            print_debug("{0} ({1}/tcp): Receiving {2} bytes...".format(self.addr, self.port, buf_size))

            # Receive the actual buffer, with respect to the MTU.
            while read_len < buf_size:
                buf_left = buf_size - read_len

                if buf_size >= mtu:
                    read_size = mtu
                else:
                    read_size = buf_left

                buf_fragment.append(self.sock.recv(read_size))
                read_len = read_len + read_size
                print_debug("{0} ({1}/tcp): Receiving {2}/{3} bytes".format(self.addr, self.port, read_len, buf_size))

            # Join the buffer fragments into one.
            buf = "".join(buf_fragment)

            # Ensure the final buffer size is what the client
            # expected it to be.
            assert buf_size == len(buf)
            
            print_debug("{0} ({1}/tcp): Received {2} bytes total".format(self.addr, self.port, len(buf)))
            return buf
        except ValueError as e:
            # Raised by socket.ntohs(). This is due to the client
            # terminating the connection abruptly.
            return None
        except Exception as e:
            print_error(e)
            traceback.print_exc()
            return None


class CallbackServer():
    """Class for callback server management."""

    def __init__(self, insecure=False, ssl_cert=None, ssl_key=None, port=443):
        """
        CallbackServer init function.

        This will start the callback server, which will listen on a TCP port.
        If encryption is enabled, and a certificate and/ or private key is not
        provided, a self-signed certificate will be automatically generated using
        OpenSSL via subprocess. The generated certificate will be deleted upon
        program termination.

        Args:
            insecure (bool):    Whether to disable TLS encryption.
            ssl_cert (str):     Path to SSL Certificate to use (Defaults to None).
            ssl_key (str):      Path to SSL Private Key to use (Defaults to None).
            port (int):         TCP Port to listen on.
        """
        self.__insecure = insecure
        if not self.__insecure:
            if ssl_cert and ssl_key:
                self.__ssl_cert = ssl_cert
                self.__ssl_key = ssl_key
            else:
                self.__gen_ssl_cert()
        self.__mtu = 1500
        self.__port = port
        self.__sock = self.__get_sock()

    def __get_sock(self):
        """
        Opens a TCP socket on a specified port.

        Hardcoded limit of 10 connections at any time.

        Returns:
            socket: The socket created by this function will be returned.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.__port))
        except socket.error:
            print_error("Socket address still in use, try again in a few minutes time.")
            return None
        sock.listen(10)
        return sock

    def __terminate(self):
        """Terminate the callback server."""
        try:
            # Sanity check.
            if self.__sock:
                self.__sock.shutdown(socket.SHUT_RDWR)
                self.__sock.close()
            # Clean up auto-generated SSL/TLS certificate and key.
            subprocess.Popen(["rm", "-rf", AUTOSSL_PATH])
            return True
        except Exception as e:
            print_error(e)
            traceback.print_exc()
            return None

    def __gen_ssl_cert(self):
        """Generates a self-signed certificate via OpenSSL."""
        try:
            __key_curve = "secp521r1"
            subprocess.check_call(["rm", "-rf", AUTOSSL_PATH])
            subprocess.check_call(["mkdir", "-p", AUTOSSL_PATH])
            subprocess.check_call(["openssl", "ecparam", "-name", __key_curve, "-genkey",
                                "-noout", "-out", "{0}/key.pem".format(AUTOSSL_PATH)])
            subprocess.check_call("openssl req -subj '/CN=L2pivot/O=zxlim/C=SG' \
                                -new -x509 -key {0}/key.pem -sha384 \
                                -days 90 -out {0}/cert.pem".format(AUTOSSL_PATH), shell=True)
        except subprocess.CalledProcessError as e:
            print_error(e)
            traceback.print_exc()
            return None
        self.__ssl_cert = "{0}/cert.pem".format(AUTOSSL_PATH)
        self.__ssl_key = "{0}/key.pem".format(AUTOSSL_PATH)
        print_good("Generated new TLS certificate with ECDSA ({0}) key.".format(__key_curve))
        return True

    def run(self):
        """Run the callback server."""
        if not self.__sock:
            return 1

        inputs = [self.__sock]
        sock_dict, tap_dict = {}, {}

        if self.__insecure:
            print_bad("TLS Encryption disabled. TRAFFIC IS NOT ENCRYPTED!")
        else:
            if not self.__ssl_cert or not self.__ssl_key:
                # Encyption is enabled, but somehow there are no certificates
                # or keys to use. Terminate immediately.
                self.__terminate()
                return 1
            print_good("TLS Encryption enabled.")
        print_info("Callback Server listening on port {0}/tcp.".format(self.__port))

        try:
            while True:
                r, w, x = select(inputs, [], [])

                for s in r:
                    if s is self.__sock:
                        # New client callback.
                        conn, addr = self.__sock.accept()

                        if self.__insecure:
                            # No encryption.
                            client_sock = conn
                        else:
                            # Create SSL context wrapper for the socket.
                            wrapper = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                            wrapper.load_cert_chain(certfile=self.__ssl_cert, keyfile=self.__ssl_key)
                            wrapper.options &= ssl.PROTOCOL_TLS & ssl.OP_NO_SSLv2 & ssl.OP_NO_SSLv3 \
                                            & ssl.OP_NO_TLSv1 & ssl.OP_NO_TLSv1_1
                            wrapper.set_ciphers("EECDH+AESGCM:AES256+EECDH")
                            client_sock = wrapper.wrap_socket(conn, server_side=True)

                        client = Client(client_sock, addr[0], addr[1])

                        # Request for a new IP Address from the pivoted network
                        # on the TAP interface.
                        client.tap.dhcp()

                        inputs.append(client.sock)
                        inputs.append(client.tap.tap)

                        sock_dict[client.sock] = client
                        tap_dict[client.tap.tap] = client

                    else:
                        if s in sock_dict:
                            # Client socket.
                            client = sock_dict[s]

                            buf = client.crecv(self.__mtu)

                            if buf is None or len(buf) == 0 or buf == "CLIENT_CLOSE":
                                # Client closed connection.
                                inputs.remove(client.sock)
                                inputs.remove(client.tap.tap)

                                sock_dict.pop(client.sock)
                                tap_dict.pop(client.tap.tap)

                                client.disconnect()
                            else:
                                # Write data from client to TAP interface.
                                client.tap.twrite(buf)

                        elif s in tap_dict:
                            # TAP Interface.
                            client = tap_dict[s]
                            # Read data from TAP interface and send to client.
                            buf = client.tap.tread()
                            client.csend(buf, self.__mtu)

        except KeyboardInterrupt, SystemExit:
            # Line break.
            print("")
            print_bad("Keyboard interrupt detected.")
        except Exception as e:
            print_error(e)
            traceback.print_exc()
            return 1
        finally:
            for s in sock_dict:
                sock_dict[s].disconnect()
            self.__terminate()
            print_info("Exiting...")
        return 0


def parse_arguments():
    parser = ArgumentParser(description="Layer 2 Pivot Callback Server. Root privileges are required to run the server.")

    parser.add_argument("-p", "--port", type=int, default=443,
                        help="The port to listen on. Listens on 443/tcp by default.")
    parser.add_argument("-c", "--cert", type=str,
                        help="Absolute path to custom TLS certificate to use for encryption.")
    parser.add_argument("-k", "--key", type=str,
                        help="Absolute path to custom private key to use for encryption.")
    parser.add_argument("-I", "--insecure", action="store_true", default=False,
                        help="Disable encrypted callback via TLS encryption.")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debugging mode (Verbose).")
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.debug:
        global DEBUG
        DEBUG = True
        print_debug("Debugging enabled.")

    server = CallbackServer(insecure=args.insecure, ssl_cert=args.cert, ssl_key=args.key, port=args.port)
    sys.exit(server.run())

if __name__ == "__main__":
    sys.exit(main())