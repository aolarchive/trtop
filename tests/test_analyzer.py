__author__ = 'Thomas Kountis'

import unittest
from trtop.whitelisting import BaseWhitelist
from trtop.resolver import BaseResolver
from trtop.collector import BaseCollector
from trtop.analyzer import OutgoingTCPAnalyzer
from appmetrics import metrics
from tcpdump.parser import is_valid_line, build_packet


#######################################
#          FUNCTIONAL TESTS           #
#######################################

class MockWhitelist(BaseWhitelist):

    def __init__(self, hosts):
        BaseWhitelist.__init__(self)
        self.hosts = hosts

    def allow(self, host, port):
        return host in self.hosts


class MockResolver(BaseResolver):

    def __init__(self, hostname):
        BaseResolver.__init__(self)
        self.hostname = hostname

    def resolve(self, addr, port):
        return self.hostname


class MockFileReaderCollector(BaseCollector):

    def __init__(self, analyser, dump_filename):
        BaseCollector.__init__(self, None)
        self.analyser = analyser
        self.dump_filename = dump_filename

    def start(self):
        with open(self.dump_filename) as tcpdump:
            for line in tcpdump:
                if is_valid_line(line):
                    self.analyser.analyse(build_packet(line))

    def stop(self):
        pass


class HealthyRemoteAnalyzerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.whitelister = MockWhitelist(["255.255.255.255"])
        cls.resolver = MockResolver("test")
        cls.analyzer = OutgoingTCPAnalyzer(cls.whitelister, cls.resolver)
        cls.collector = MockFileReaderCollector(cls.analyzer, "healthy_remote_test.dump")
        cls.collector.start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()
        [metrics.delete_metric(metric) for metric in metrics.metrics()]

    def test_syn(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_syn_count(), 1)

    def test_ack(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_syn_ack_count(), 1)

    def test_est(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_est_count(), 1)

    def test_rst(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_rst_count(), 0)

    def test_fin(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_fin_in_count(), 1)
        self.assertEquals(state.get_fin_out_count(), 0)

    def test_out(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_outgoing_count(), 2)

    def test_in(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_incoming_count(), 2)

    def test_err(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_pkt_err_count(), 0)

    def test_retransmit(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_retransmit_counter(), 0)


class HealthyPreConnectedRemoteAnalyzerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.whitelister = MockWhitelist(["255.255.255.255"])
        cls.resolver = MockResolver("test")
        cls.analyzer = OutgoingTCPAnalyzer(cls.whitelister, cls.resolver)
        cls.collector = MockFileReaderCollector(cls.analyzer, "healthy_pre_connected_remote_test.dump")
        cls.collector.start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()
        [metrics.delete_metric(metric) for metric in metrics.metrics()]

    def test_syn(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_syn_count(), 0)

    def test_ack(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_syn_ack_count(), 0)

    def test_est(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_est_count(), 0)

    def test_rst(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_rst_count(), 0)

    def test_fin(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_fin_in_count(), 1)
        self.assertEquals(state.get_fin_out_count(), 0)

    def test_out(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_outgoing_count(), 2)

    def test_in(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_incoming_count(), 2)

    def test_err(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_pkt_err_count(), 0)

    def test_retransmit(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_retransmit_counter(), 0)


class LoopbackRemoteAnalyzerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.whitelister = MockWhitelist(["127.0.0.1"])
        cls.resolver = MockResolver("test")
        cls.analyzer = OutgoingTCPAnalyzer(cls.whitelister, cls.resolver)
        cls.collector = MockFileReaderCollector(cls.analyzer, "loopback_test.dump")
        cls.collector.start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()
        [metrics.delete_metric(metric) for metric in metrics.metrics()]

    def test_syn(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_syn_count(), 184)

    def test_ack(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_syn_ack_count(), 171)

    def test_est(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_est_count(), 171)

    def test_rst(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_rst_count(), 13)

    def test_fin(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_fin_in_count(), 24)
        self.assertEquals(state.get_fin_out_count(), 0)

    def test_out(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_outgoing_count(), 909)

    def test_in(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_incoming_count(), 871)

    def test_err(self):
        state = self.__class__.analyzer.tracked_remotes.get('test')
        self.assertEquals(state.get_pkt_err_count(), 0)