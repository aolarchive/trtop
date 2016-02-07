__author__ = 'Thomas Kountis'


class BaseAnalyser(object):

    def analyse(self, packet):
        pass


import sys
import logging
import traceback
from state import *


class OutgoingTCPAnalyzer(BaseAnalyser):
    """
    TCP Packet analyzing
    Outgoing connections only, initiated after monitoring started!
    """

    def __init__(self, whitelist, resolver):
        BaseAnalyser.__init__(self)
        self.tracked_remotes = {}
        self.whitelist = whitelist
        self.resolver = resolver
        self.observer = None

    def set_observer(self, observer):
        logging.debug("Observer is now %s", observer)
        self.observer = observer

    def notify_observer(self, tcp_remote):
        self.observer.handle_remote_event(tcp_remote)

    def analyse(self, unified_packet):
        logging.debug("Analyzing %s", unified_packet)

        try:
            # TODO handle DNS traffic separate functions
            hostname = self.resolver.resolve(unified_packet.remote_ip(), unified_packet.remote_port())
            tcp_remote = self.tracked_remotes.get(hostname)
            logging.debug("Packet remote resolved to: %s", str(hostname))

            if tcp_remote is None:
                if not self.whitelist.allow(unified_packet.remote_ip(), unified_packet.remote_port()):
                    return

                tcp_remote = TcpRemoteState(hostname)
                self.tracked_remotes[hostname] = tcp_remote

            if self._handle_action(tcp_remote, unified_packet) and self.observer is not None:
                self.notify_observer(tcp_remote)

        except Exception, e:
            logging.exception("Exception during packet: " + str(unified_packet))
            logging.exception(e, exc_info=True)
            raise e

    def _handle_action(self, tcp_remote, unified_packet):
        if not tcp_remote.verify_and_track_seq(unified_packet):
            return False

        action = {
            'S': lambda: tcp_remote.process_syn(unified_packet),
            'S.': lambda: tcp_remote.process_syn_ack(unified_packet),

            '.': lambda: tcp_remote.process_ack(unified_packet),

            'R': lambda: tcp_remote.process_rst(unified_packet),
            'R.': lambda: tcp_remote.process_rst(unified_packet),

            'P': lambda: tcp_remote.process_psh(unified_packet),
            'P.': lambda: tcp_remote.process_psh(unified_packet),

            'FP.': lambda: tcp_remote.process_psh(unified_packet, fin=True),
            'F.': lambda: tcp_remote.process_fin(unified_packet),
            'F': lambda: tcp_remote.process_fin(unified_packet)
        }.get(unified_packet.flags)

        logging.debug("Packet action identifier %s", str(unified_packet.flags))
        return action() if action is not None else False

    def _dns_resolved(self, host, hostname):
        self.tracked_remotes[host].hostname = hostname