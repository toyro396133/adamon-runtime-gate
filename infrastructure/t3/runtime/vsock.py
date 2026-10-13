"""Firecracker host UDS-to-vsock handshake; local socket capability only."""
import socket
from .microvm import Blocked


def connect_guest(connected_socket, timeout=10):
    if connected_socket.family!=socket.AF_UNIX or type(timeout) not in (int,float) or not 0<timeout<=30:
        raise Blocked('LOCAL_VSOCK_REQUIRED')
    connected_socket.settimeout(timeout)
    # Fixed guest init port. Neither port nor socket path is workflow-controlled.
    connected_socket.sendall(b'CONNECT 52\n')
    line=bytearray()
    while not line.endswith(b'\n'):
        part=connected_socket.recv(1)
        if not part: raise Blocked('VSOCK_HANDSHAKE_TRUNCATED')
        line.extend(part)
        if len(line)>64: raise Blocked('VSOCK_HANDSHAKE_LIMIT')
    # Firecracker returns "OK <host-port>\n"; no remote endpoint is accepted.
    fields=bytes(line).split()
    if len(fields)!=2 or fields[0]!=b'OK' or not fields[1].isdigit() or not 0<int(fields[1])<=2**32-1:
        raise Blocked('VSOCK_HANDSHAKE_REJECTED')
    return connected_socket
