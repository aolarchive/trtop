from appmetrics import metrics
import logging

__author__ = 'Thomas Kountis'

TCP_FLAG_SYN = 'S'
TCP_FLAG_SYN_ACK = 'S.'
TCP_FLAG_ACK = '.'
TCP_FLAG_PSH_ACK = 'P.'

COUNTER_SYN = "_syn_counter"
COUNTER_SYN_ACK = "_syn_ack_counter"
COUNTER_EST = "_est_counter"
COUNTER_RST = "_rst_counter"
COUNTER_FIN_IN = "_fin_in_counter"
COUNTER_FIN_OUT = "_fin_out_counter"
COUNTER_PKT_OUT = "_packet_out_counter"
COUNTER_PKT_IN = "_packet_in_counter"
COUNTER_PKT_ERR = "_pkt_err_counter"
COUNTER_RTRS = "_retransmits_counter"
HISTOGRAM_CONN = "_conn_time_histo"
HISTOGRAM_TRANSPORT = "_transport_time_histo"
HISTOGRAM_RT_PER_CONN = "_rt_per_conn_histo"


class TcpSessionState:

    def __init__(self, remote_addr, syn_ts=None, local_seq=0):
        self.remote_addr = remote_addr
        self.syn_ts = syn_ts
        self.est_ts = 0
        self.last_known_flag = TCP_FLAG_SYN if syn_ts else None
        self.datagram_out_ts = None
        self.datagram_out_seq = None
        self.rt_packet_count = 0
        self.local_sequence = local_seq
        self.remote_sequence = 0

    def is_untracked_conn(self):
        return self.last_known_flag is None

    def is_established(self):
        return self.last_known_flag is not TCP_FLAG_SYN and \
               self.last_known_flag is not TCP_FLAG_SYN_ACK

    def __str__(self):
        return "{0} {1} - rt: {2} loc_seq: {3}, rem_seq: {4}"\
            .format(self.remote_addr, self.last_known_flag, self.rt_packet_count,
                    self.local_sequence, self.remote_sequence)


class TcpRemoteState(object):

        def __init__(self, hostname):
            self.hostname = hostname
            self.syn_counter = metrics.new_meter(str(hostname) + COUNTER_SYN)
            self.syn_ack_counter = metrics.new_meter(str(hostname) + COUNTER_SYN_ACK)
            self.est_counter = metrics.new_meter(str(hostname) + COUNTER_EST)
            self.resets_counter = metrics.new_meter(str(hostname) + COUNTER_RST)
            self.fin_in_counter = metrics.new_meter(str(hostname) + COUNTER_FIN_IN)
            self.fin_out_counter = metrics.new_meter(str(hostname) + COUNTER_FIN_OUT)
            self.connection_time = metrics.new_histogram(str(hostname) + HISTOGRAM_CONN)
            self.outgoing_packets = metrics.new_meter(str(hostname) + COUNTER_PKT_OUT)
            self.incoming_packets = metrics.new_meter(str(hostname) + COUNTER_PKT_IN)
            self.transport_time = metrics.new_histogram(str(hostname) + HISTOGRAM_TRANSPORT)
            self.rt_per_conn_counter = metrics.new_histogram(str(hostname) + HISTOGRAM_RT_PER_CONN)
            self.pkt_err_counter = metrics.new_counter(str(hostname) + COUNTER_PKT_ERR)
            self.retransmits_counter = metrics.new_counter(str(hostname) + COUNTER_RTRS)
            self.states = {}

        def verify_and_track_seq(self, packet):
            state = self.states.get(packet.ephemeral_port())
            if state is None:
                return True

            curr_seq = state.remote_sequence if packet.is_outgoing() else state.local_sequence
            if curr_seq + 1 == packet.ack or curr_seq == packet.ack:
                self._track_sequence(state, packet)
                return True

            self.pkt_err_counter.notify(1)
            logging.debug("SEQ verification failed for packet {0} during state {1}".format(packet, state))
            del self.states[packet.ephemeral_port()]
            return False

        def _track_sequence(self, state, packet):
            if packet.is_ack_only():  # ACK only packet - No SEQ included.
                return

            if packet.is_outgoing():
                state.local_sequence = packet.sequence
            else:
                state.remote_sequence = packet.sequence

        def process_syn(self, packet):
            state = self.states.get(packet.ephemeral_port())
            if state is None:
                self.states[packet.ephemeral_port()] = TcpSessionState(packet.remote_ip(), packet.timestamp, packet.sequence)
                self.syn_counter.notify(1)
                return True
            else:
                self.pkt_err_counter.notify(1)
                #TODO handle re-transmits upto 20secs /sysctl/ -- net.ipv4.tcp_syn_retries
                warning("--ERROR({0})-- incorrect state {1} for new bit {2} identified for a given packet {3}."
                        .format("handle_syn", state, TCP_FLAG_SYN, packet))
            return False

        def process_syn_ack(self, packet):
            state = self.states.get(packet.ephemeral_port())
            if state is None:
                # Ignore packet if not seen SYN before hand / old connection!
                return False
            elif TCP_FLAG_SYN == state.last_known_flag:
                state.last_known_flag = TCP_FLAG_SYN_ACK
                self.syn_ack_counter.notify(1)
                return True
            else:
                self.pkt_err_counter.notify(1)
                warning("--ERROR({0})-- incorrect state {1} for new bit {2} identified for a given packet {3}."
                        .format("handle_syn_ack", state, TCP_FLAG_SYN_ACK, packet))
            return False

        def process_ack(self, packet):
            # TODO handle ACK with Data packets (no PUSH flag) len > 0
            state = self.states.get(packet.ephemeral_port())
            if state is None:
                # Ignore
                return False
            elif TCP_FLAG_SYN_ACK == state.last_known_flag:
                state.last_known_flag = TCP_FLAG_ACK
                state.est_ts = packet.timestamp
                duration = ((float(packet.timestamp) * 1e6) - (float(state.syn_ts) * 1e6)) / 1000  # us to ms
                self.connection_time.notify(duration)
                self.est_counter.notify(1)
                return True
            else:
                # Ignore ACKs (only) following states other than SYN
                # Sequence is tracked anyway, they offer no other useful information
                return False

        def process_psh(self, packet, fin=False):
            state = self.states.get(packet.ephemeral_port())

            incoming = not packet.is_outgoing()
            if incoming and state is not None:
                if TCP_FLAG_PSH_ACK == state.last_known_flag:  # Expect request before response
                    # If length > 1400 then its more than one segment, so wait for next before finalizing duration
                    # TODO figure a dynamic way of identifying the 1400 value, looks like MSS - 60 or sysctl value?
                    if packet.length >= 1400:
                        return False

                    outgoing_ts = state.datagram_out_ts
                    duration = ((float(packet.timestamp) * 1e6) - (float(outgoing_ts) * 1e6)) / 1000  # us to ms
                    state.rt_packet_count += 1

                    self.transport_time.notify(duration)
                    self.incoming_packets.notify(1)
                else:
                    self.pkt_err_counter.notify(1)

            elif packet.is_outgoing():
                # Start tracking connection from first identified outgoing PUSH.
                # TODO have that as a flag for trtop (track existing)
                if state is None:
                    self.states[packet.ephemeral_port()] = \
                        TcpSessionState(packet.remote_ip(), local_seq=packet.sequence)
                    state = self.states.get(packet.ephemeral_port())

                if state.is_untracked_conn() or state.is_established():
                    # TODO Should save the flag as seen in the packet, not hard-coded TCP_FLAG_PSH_ACK
                    state.last_known_flag = TCP_FLAG_PSH_ACK
                    state.datagram_out_ts = packet.timestamp

                    if packet.length >= 1400:
                        return False

                    self.outgoing_packets.notify(1)
                else:
                    self.pkt_err_counter.notify(1)
            else:
                self.pkt_err_counter.notify(1)
                warning("--ERROR({0})-- incorrect state {1} -- outgoing {2}."
                        .format("handle_psh", state, packet.is_outgoing()))

            if fin:
                self._track_rt_per_connection(packet.ephemeral_port())
                del self.states[packet.ephemeral_port()]
                self.fin_out_counter.notify(1) if packet.is_outgoing() else self.fin_in_counter.notify(1)

            return True

        def process_rst(self, packet):
            state = self.states.get(packet.ephemeral_port())
            if state is None:
                # Ignore
                return False
            else:
                del self.states[packet.ephemeral_port()]
                self.resets_counter.notify(1)
                return True

        def process_fin(self, packet):
            state = self.states.get(packet.ephemeral_port())
            if state is None:
                # Ignore
                return False

            # TODO deleting will make followup FIN exchanges to not be monitored - feature not a bug.
            self._track_rt_per_connection(packet.ephemeral_port())
            del self.states[packet.ephemeral_port()]
            self.fin_out_counter.notify(1) if packet.is_outgoing() else self.fin_in_counter.notify(1)
            return True

        def _track_rt_per_connection(self, local_port):
            pkt_count = self.states[local_port].rt_packet_count
            if pkt_count > 0:
                self.rt_per_conn_counter.notify(pkt_count)

        def get_syn_count(self):
            return self.syn_counter.get()['count']

        def get_syn_mean_rate(self):
            return self.syn_counter.get()['mean']

        def get_syn_ack_count(self):
            return self.syn_ack_counter.get()['count']

        def get_est_count(self):
            return self.est_counter.get()['count']

        def get_rst_count(self):
            return self.resets_counter.get()['count']

        def get_fin_out_count(self):
            return self.fin_out_counter.get()['count']

        def get_fin_in_count(self):
            return self.fin_in_counter.get()['count']

        def get_est_mean_rate(self):
            return self.est_counter.get()['mean']

        def get_retransmit_counter(self):
            return self.retransmits_counter.get()['value']

        def get_conn_latency_mean(self):
            return self.connection_time.get()['arithmetic_mean']

        def get_conn_latency_95th(self):
            return self.connection_time.get()['percentile'][3][1]

        def get_conn_latency_min(self):
            return self.connection_time.get()['min']

        def get_conn_latency_max(self):
            return self.connection_time.get()['max']

        def get_transport_rtt_95th(self):
            return self.transport_time.get()['percentile'][3][1]

        def get_incoming_count(self):
            return self.incoming_packets.get()['count']

        def get_outgoing_count(self):
            return self.outgoing_packets.get()['count']

        def get_rt_per_conn_95th(self):
            count = self.rt_per_conn_counter.get()['n']
            return self.rt_per_conn_counter.get()['percentile'][3][1] if count > 0 else '*'

        def get_pkt_err_count(self):
            return self.pkt_err_counter.get()['value']

        def __str__(self):
            return "Host: {0} attempts: {1}, established: {2}, resets: {3}, success: {4:.2f}% | " \
                   "rate: {5:.2f}/s, mean_time: {6:.2f}ms, 99th_time: {7:.2f}ms, " \
                   "min: {8:.2f}ms, max: {9:.2f}ms" \
                .format(self.hostname,
                        self.get_syn_count(), self.get_est_count(),
                        self.get_rst_count(),
                        ((float(self.get_est_count()) / float(self.get_syn_count())) * 100),
                        self.get_est_mean_rate(),
                        self.get_conn_latency_mean(), self.get_conn_latency_95th(),
                        self.get_conn_latency_min(), self.get_conn_latency_max())


def warning(msg):
    logging.warning(msg)
