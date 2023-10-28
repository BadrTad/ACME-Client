import ssl
import socket

from pprint import pprint


def verify_ssl_certificate(hostname):
    context = ssl.create_default_context(cafile="./pebble_keys/pebble.minica.pem")

    with socket.create_connection(("172.30.210.4", 14000)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            ssock.do_handshake()
            cert = ssock.getpeercert()
            pprint(cert)
            print("Certificate is valid.")


verify_ssl_certificate("pebble")
