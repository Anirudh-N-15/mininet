"""What gets installed in each OpenFlow table. Pure data: no Ryu import here.

Table 0 = telemetry: a few counting rules, every one of them ends in
          "goto table 1", so counting never changes where packets go.
Table 1 = forwarding: an ordinary MAC-learning switch.

A packet matches at most ONE rule per table, so the counting rules must be
disjoint. They are, because they differ in direction (to / from the server) and
in which TCP flags are required.
"""

# TCP flag bits (RFC 9293)
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

TELEMETRY_TABLE = 0
FORWARD_TABLE = 1

# Cookies tag our rules so the stats reply can be decoded without guessing.
COOKIE_SYN = 0xE6100001     # client SYN -> server           (detector input x_n)
COOKIE_FIN = 0xE6100002     # server FIN, from server's port (evidence)
COOKIE_SYNACK = 0xE6100003  # server SYN-ACK                 (diagnostic)
COOKIE_DEFAULT = 0xE6100000  # table-0 catch-all -> table 1
COUNTER_NAMES = {COOKIE_SYN: "syn", COOKIE_FIN: "fin", COOKIE_SYNACK: "synack"}

IPV4, TCP = 0x0800, 6


def telemetry_rules(cfg):
    """[(name, priority, cookie, match_fields)] for the server's edge switch.

    match_fields is a plain dict that becomes OFPMatch(**fields).
    tcp_flags=(value, mask): bits in mask must equal bits in value.
    """
    to_server = dict(eth_type=IPV4, ip_proto=TCP,
                     ipv4_dst=cfg.server_ip, tcp_dst=cfg.server_tcp_port)
    # in_port pins the evidence to the server's own cable: an outside host
    # cannot inject packets that arrive on that port, so it cannot fake FINs.
    from_server = dict(in_port=cfg.server_ofport, eth_type=IPV4, ip_proto=TCP,
                       ipv4_src=cfg.server_ip, tcp_src=cfg.server_tcp_port)
    return [
        # SYN set, ACK clear = a connection *attempt* (not the server's SYN-ACK)
        ("syn", 100, COOKIE_SYN, dict(to_server, tcp_flags=(SYN, SYN | ACK))),
        # FIN set = the server is closing a connection that really existed
        ("fin", 100, COOKIE_FIN, dict(from_server, tcp_flags=(FIN, FIN))),
        # SYN+ACK = server answered an attempt (useful to explain the plots)
        ("synack", 90, COOKIE_SYNACK,
         dict(from_server, tcp_flags=(SYN | ACK, SYN | ACK | FIN))),
    ]
