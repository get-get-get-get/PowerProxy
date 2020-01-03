#!/usr/bin/env python3
import argparse
import logging
import logging.handlers
import os
import select
import socket
import ssl
import sys
import threading
import time
import queue


class ProxyHandler:

    def __init__(self, proxy_addr, proxy_port, listen_addr, listen_port):

        # Server that handles clients
        self.client_address = proxy_addr
        self.client_port = int(proxy_port)
        self.client_listener_sock = None
        # Server that handles remote proxies
        self.reverse_address = listen_addr
        self.reverse_port = int(listen_port)
        self.reverse_listener_sock = None

        # SSL/TLS (for connection w/ remote proxies)
        self.ssl_context = None
        # Paths to cert files
        self.ssl_cert = None
        self.ssl_key = None

        # Active connections to remote proxies (sockets)
        self.remote_sockets = queue.Queue()

    # SSL/TLS for connection with remote proxies
    def set_ssl_context(self, certificate=None, private_key=None, verify=True):

        # Create SSL context using highest TLS version available for client & server.
        # Uses system certs (?). verify_mode defaults to CERT_REQUIRED
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
        )

        # Don't check hostname
        ssl_context.check_hostname = False

        # Store paths to cert and key files, for idk why
        if certificate:
            self.ssl_cert = os.path.abspath(certificate)
        if private_key:
            self.ssl_key = os.path.abspath(private_key)

        # Use custom cert/key if given
        if self.ssl_cert and self.ssl_key:
            ssl_context.load_cert_chain(self.ssl_cert, self.ssl_key)

        # Don't be a dick about certs:
        if not verify:
            ssl_context.verify_mode = ssl.CERT_OPTIONAL
        
        self.ssl_context = ssl_context
        logger.debug("[^] Set SSL context: {}".format(ssl_context))

    # Master thread
    def serve(self):

        if not self.ssl_context:
            logger.warning("[!] WARNING: SSL context not set. Connections to reverse proxies will not be encrypted!")

        try:
            # Listen for connections from reverse proxies
            reverse_listener = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            reverse_listener.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            reverse_listener.bind((self.reverse_address, self.reverse_port))
            self.reverse_listener_sock = reverse_listener

            # TODO: set threadnames, for better logging
            reverse_listener_t = threading.Thread(
                target=self.listen_for_reverse,
                args=[reverse_listener, ],
                name="reverse_listener"
            )
            reverse_listener_t.start()
            logger.info("[^] Listening for reverse proxies on {}:{}".format(
                self.reverse_address, self.reverse_port))

            # Listen for clients
            client_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_listener.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_listener.bind((self.client_address, self.client_port))
            self.client_listener_sock = client_listener

            client_listener_t = threading.Thread(
                target=self.listen_for_client,
                args=[client_listener, ],
                name="client_listener"
            )
            client_listener_t.start()
            logger.info("[^] Listening for clients on {}:{}".format(
                self.client_address, self.client_port))

            # TODO: some sort of monitoring process. Temporarily just join() thread to keep proc going
            client_listener_t.join()

        except Exception as e:
            logger.error("[!] ERROR in master thread: {}".format(e))
            raise e
        finally:
            self.kill_local_process()

    # Close all sockets and threads, then exit. Does not send kill signal to remote machines
    def kill_local_process(self):

        self.reverse_listener_sock.close()
        self.client_listener_sock.close()

        while not self.remote_sockets.empty():
            s = self.remote_sockets.get()
            s.close()

        exit()

    # Send "KILL" message to reverse proxies
    def kill_reverse_process(self, address=None):

        # TODO - This will send 'KILL' message to waiting reverse proxies
        # Indicates to close all connections (ALL connections?) and don't try to connect back
        # Reverse proxies should reply 'DEAD' to confirm they got message (not critical)

        # Limit KILL to a given host
        if address:
            logger.info(
                "[-] Sending 'KILL' message to reverse proxies at {}".format(address))
            # TODO
            pass
        # Kill all
        else:
            logger.info("[-] Sending 'KILL' message to all reverse proxies")
            # TODO
            pass

    # Listen for incoming connections from reverse proxies
    def listen_for_reverse(self, listen_socket, backlog=20):

        # Start listening
        listen_socket.listen(backlog)

        # Track known reverse machines
        known_connections = set()

        while True:

            # Accept connection, not yet encrypted
            clear_socket, address = listen_socket.accept()
            logger.debug(
                "[+] New reverse connection from {}:{}".format(address[0], address[1]))

            # Encrypt connection
            if self.ssl_context:
                reverse_socket = self.ssl_context.wrap_socket(
                    clear_socket, server_side=True)
                logger.debug("[^] Encrypted connection with {}".format(address))
            else:
                reverse_socket = clear_socket

            # Store socket for use with client later
            self.remote_sockets.put(reverse_socket)

            # Announce connection if new remote address
            if address[0] not in known_connections:
                known_connections.add(address[0])
                logger.info("[+] New reverse proxy: {}".format(address[0]))

    # Listen for proxy clients
    def listen_for_client(self, srv_sock, backlog=10):

        srv_sock.listen(backlog)

        while True:
            client_socket, address = srv_sock.accept()
            address = f"{address[0]}:{address[1]}"
            logger.info("[*] Client connected from {}".format(address))

            forward_conn_t = threading.Thread(
                target=self.forward_connection,
                args=[client_socket, ],
                name=f"forward_client_{address}",
                daemon=True,
            )
            forward_conn_t.start()

    # Proxy connection between client and remote
    def forward_connection(self, client_socket, reverse_socket=None, wait=5, max_fails=10):

        reverse_socket = self.get_available_reverse(wait=wait, max_attempts=max_fails)
        
        # Get basic info on client/remote
        client_name = client_socket.getpeername()
        remote_name = reverse_socket.getpeername()

        # debug message
        logger.debug("[_] Tunneling {} through {}".format(
            client_name, remote_name, ))

        # Send reverse_socket "WAKE" message to wake for proxying
        self.wake_reverse(reverse_socket)

        #######################
        # FORWARDING
        ############

        reverse_socket.setblocking(False)
        client_socket.setblocking(False)

        while True:
            receivable, writable, exceptional = select.select(
                [reverse_socket, client_socket], [reverse_socket, client_socket], [])

            for sock in receivable:

                if sock is reverse_socket:
                    data = b''
                    while True:
                        try:
                            buf = reverse_socket.recv(2048)
                        except Exception as e:
                            logger.debug(
                                "[!] Error receiving from remote: {}".format(e))
                            break

                        if len(buf) == 0:
                            break
                        else:
                            data += buf
                    if len(data) != 0:
                        client_socket.sendall(data)

                if sock is client_socket:
                    data = b''
                    while True:
                        try:
                            buf = client_socket.recv(2048)
                        except Exception as e:
                            logger.debug(
                                "[!] Error receiving from client: {}".format(e))
                            break

                        if len(buf) == 0:
                            break
                        else:
                            data += buf
                    if len(data) != 0:
                        reverse_socket.sendall(data)

    # Return socket connected to reverse proxy
    def get_available_reverse(self, wait=1, max_attempts=5):

        reverse_socket = None

        try:
            reverse_socket = self.remote_sockets.get()
        # Don't know the specific exception when getting from empty queue (TODO)
        except Exception as e:

            logger.error("[!] No reverse proxies available: {}".format(e))
            logger.debug(
                "[^] Waiting {} seconds (at most) for a proxy to connect".format(wait * max_attempts))

            for i in range(max_attempts - 1):
                time.sleep(wait)
                try:
                    reverse_socket = self.remote_sockets.get()
                    break
                except:
                    pass

            if not reverse_socket:
                logger.error(
                    "[!] No proxies showed up! Killing process and exiting...")
                self.kill_local_process()
                raise
        
        return reverse_socket


    # Send 'WAKE' message to waiting reverse proxy. Return reply message
    def wake_reverse(self, reverse_sock, max_attempts=5):

        reply = None 

        reverse_sock.send("WAKE".encode())
        data = reverse_sock.recv(2048)

        i = 0
        while not (len(data) == 4):
            data += reverse_sock.recv(2048)
            if i == max_attempts:
                break
            else:
                i += 1


        logger.debug("[^] Reverse proxy replied: {}".format(data))
        if data != b"WOKE":
            logger.error("[!] Unexpected reply from reverse proxy: {}".format(data))
            # raise
        else:
            reply = 'WOKE'
        return reply


def main():

    # Address/port for server(s)
    reverse_address = args.reverse_address
    reverse_port = args.reverse_port
    client_address = args.client_address
    client_port = args.client_port

    # Instantiate ProxyHandler
    proxy_handler = ProxyHandler(
        client_address, client_port, reverse_address, reverse_port)

    # Set SSL for ProxyHandler (or don't)
    if not args.no_encrypt:
        proxy_handler.set_ssl_context(
            certificate=args.cert,
            private_key=args.key,
            verify=args.verify_certs
        )

    proxy_handler.serve()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ##########
    # Listener options
    #####
    # Listening for connections from reverse proxies
    parser.add_argument(
        "-p",
        "--reverse-port",
        default=443,
        type=int,
        help="Port to listen for reverse proxies connecting"
    )
    parser.add_argument(
        "-i",
        "--reverse-address",
        default="",
        help="IP address to listen for reverse proxies connecting"
    )
    # Listening for connections from SOCKS clients
    parser.add_argument(
        "-P",
        "--client-port",
        default=1080,
        type=int,
        help="Port to listen for clients connecting"
    )
    parser.add_argument(
        "-I",
        "--client-address",
        default="127.0.0.1",
        help="IP address to listen for clients connecting"
    )

    ##########
    # SSL/TLS options
    #####
    parser.add_argument(
        "-c",
        "--cert",
        default=None,
        help="Path to certificate"
    )
    parser.add_argument(
        "-k",
        "--key",
        default=None,
        help="Path to private key"
    )
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="Don't encrypt connections with remote proxies"
    )
    parser.add_argument(
        "--verify-certs",
        default=False,
        action="store_true",
        help="Use ssl.CERT_REQUIRED for SSL/TLS context (default: ssl.CERT_OPTIONAL)"
    )

    ##########
    # Output & logging options
    #####
    parser.add_argument(
        "-l",
        "--logfile",
        help="Log file"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output and logging"
    )

    # Parse arguments
    args = parser.parse_args()

    ##########
    # LOGGING
    #####
    global logger

    # Create queue (no size limit), handled by a QueueHandler instance
    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)

    # Set logger to use QueueHandler
    logger = logging.getLogger()
    logger.addHandler(queue_handler)
    # logger.setLevel(logging.DEBUG)

    # LOG HANDLERS

    # Console logger - "console_logger"
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('{message}', style='{')
    console_handler.setFormatter(console_formatter)
    if args.verbose:
        # console_handler.setLevel("DEBUG")
        logger.setLevel("DEBUG")
    else:
        # console_handler.setLevel("INFO")
        logger.setLevel("INFO")

    # File logger - "file_logger"
    if args.logfile:
        file_handler = logging.FileHandler(filename=args.logfile)
    else:
        file_handler = logging.NullHandler()
    file_formatter = logging.Formatter(
        '[{threadName}] - {asctime} - {message}', style='{')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel('DEBUG')

    # Start listening for logs
    queue_listener = logging.handlers.QueueListener(
        log_queue, console_handler, file_handler)
    queue_listener.start()

    #####
    # /LOGGING
    ##########

    # Hope this doesn't fuck this up, but structured so listener will always stop on program exit
    try:
        main()
    finally:
        queue_listener.stop
