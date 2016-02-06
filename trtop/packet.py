__author__ = 'Thomas Kountis'


from utils import cat

MIN_EPHEMERAL_PORT = int(cat("/proc/sys/net/ipv4/ip_local_port_range", default="32788").split("\t")[0])
TCP_FLAG_ACK = '.'


class UnifiedPacket:

    def __init__(self):
        self.src = None
        self.src_port = None
        self.dst = None
        self.dst_port = None
        self.flags = None
        self.timestamp = None
        self.ack = None
        self.sequence = None
        self.length = None

    def is_outgoing(self):
        return self.src_port >= MIN_EPHEMERAL_PORT

    def remote_ip(self):
        if self.src_port < MIN_EPHEMERAL_PORT:
            return self.src

        return self.dst

    def remote_port(self):
        if self.src_port < MIN_EPHEMERAL_PORT:
            return self.src_port

        return self.dst_port

    def local_ip(self):
        if self.src_port < MIN_EPHEMERAL_PORT:
            return self.dst

        return self.src

    def ephemeral_port(self):
        if self.src_port < MIN_EPHEMERAL_PORT:
            return self.dst_port

        return self.src_port

    def is_ack_only(self):
        return self.flags == TCP_FLAG_ACK and self.length == 0

    def __str__(self):
        return "{0} {1} {2}:{3} > {4}:{5} [{6}] (ephemeral: {7}, remote_ip: {8}, " \
               "remote_port: {9}, ack: {10}, seq: {11}) (len: {12})" \
            .format(self.timestamp, "out" if self.is_outgoing() else "in", self.src, self.src_port,
                    self.dst, self.dst_port, self.flags, self.ephemeral_port(),
                    self.remote_ip(), self.remote_port(), self.ack, self.sequence, self.length)
