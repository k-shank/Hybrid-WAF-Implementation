"""Implementation of the sniffing application that uses the classification module.

This script uses Scapy to sniff incoming HTTP requests on a given port.  For
each observed request a `Request` object is created, populated with
metadata, classified via `ThreatClassifier` and persisted to the SQLite
database through `DBController`.  Run with administrative privileges
because raw packet capture requires elevated permissions on most systems.
"""

from __future__ import annotations
import urllib.parse
from argparse import ArgumentParser

from scapy.all import sniff, Raw
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession

from .request import Request, DBController
from .classifier import ThreatClassifier


def main() -> None:
    parser = ArgumentParser(description="Simple WAF packet sniffer")
    parser.add_argument('--port', type=int, default=5000, help='Port to sniff')
    parser.add_argument('--iface', type=str, default='lo', help='Interface to sniff on')
    args = parser.parse_args()

    # Bind HTTP layer to the specified port for both directions
    scapy.packet.bind_layers(TCP, HTTP, dport=args.port)
    scapy.packet.bind_layers(TCP, HTTP, sport=args.port)

    db = DBController()
    threat_clf = ThreatClassifier()

    # Define which headers to extract
    header_fields = [
        'Http_Version', 'A_IM', 'Accept', 'Accept_Charset', 'Accept_Datetime',
        'Accept_Encoding', 'Accept_Language', 'Access_Control_Request_Headers',
        'Access_Control_Request_Method', 'Authorization', 'Cache_Control',
        'Connection', 'Content_Length', 'Content_MD5', 'Content_Type', 'Cookie',
        'DNT', 'Date', 'Expect', 'Forwarded', 'From', 'Front_End_Https',
        'If_Match', 'If_Modified_Since', 'If_None_Match', 'If_Range',
        'If_Unmodified_Since', 'Keep_Alive', 'Max_Forwards', 'Origin',
        'Permanent', 'Pragma', 'Proxy_Authorization', 'Proxy_Connection', 'Range',
        'Referer', 'Save_Data', 'TE', 'Upgrade', 'Upgrade_Insecure_Requests',
        'User_Agent', 'Via', 'Warning', 'X_ATT_DeviceId', 'X_Correlation_ID',
        'X_Csrf_Token', 'X_Forwarded_For', 'X_Forwarded_Host',
        'X_Forwarded_Proto', 'X_Http_Method_Override', 'X_Request_ID',
        'X_Requested_With', 'X_UIDH', 'X_Wap_Profile'
    ]

    def get_header(packet: scapy.packet.Packet) -> dict:
        headers: dict = {}
        for field in header_fields:
            value = getattr(packet[HTTPRequest], field)
            if value and value != 'None':
                # decode bytes to string
                headers[field] = value.decode() if isinstance(value, bytes) else str(value)
        return headers

    def sniffing_function(packet: scapy.packet.Packet) -> None:
        # Only process HTTP requests
        if packet.haslayer(HTTPRequest):
            req = Request()
            # Source IP
            req.origin = packet[IP].src if packet.haslayer(IP) else 'localhost'
            req.host = urllib.parse.unquote(packet[HTTPRequest].Host.decode())
            req.request = urllib.parse.unquote(packet[HTTPRequest].Path.decode())
            req.method = packet[HTTPRequest].Method.decode()
            req.headers = get_header(packet)
            # Body
            if packet.haslayer(Raw):
                try:
                    req.body = packet[Raw].load.decode()
                except Exception:
                    req.body = ''
            # Classify and persist
            threat_clf.classify_request(req)
            db.save(req)

    # Start sniffing
    try:
        sniff(prn=sniffing_function, iface=args.iface, filter='port ' + str(args.port) + ' and inbound', session=TCPSession)
    finally:
        db.close()


if __name__ == '__main__':
    main()