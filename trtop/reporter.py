__author__ = 'Thomas Kountis'


class BaseReporter(object):

    def handle_remote_event(self, host):
        pass

    def start(self):
        pass

    def stop(self):
        pass

from resolver import DefaultDNSResolver
from whitelisting import DefaultWhitelist


class CLIEventAppendReporter(BaseReporter):

    def __init__(self, collector, analyzer, whitelist=DefaultWhitelist, resolver=DefaultDNSResolver):
        BaseReporter.__init__(self)
        self.collector_clazz = collector
        self.analyzer_clazz = analyzer
        self.whitelist_clazz = whitelist
        self.resolver_clazz = resolver
        self.collector = None

    def handle_remote_event(self, host):
        print(host)

    def start(self):
        self.collector = self.collector_clazz(
            self.analyzer_clazz(self, self.whitelist_clazz(), self.resolver_clazz()))
        self.collector.start()

    def stop(self):
        self.collector.stop()


import curses
import time
import locale

locale.setlocale(locale.LC_ALL,"")


class CLICursesOutgoingTCPReporter(BaseReporter):
    """
    Curses based reporter for the @analyzer.OutgoingTCPAnalyzer
    Refreshing time based, and controlled with the REFRESH_RATE class property.
    """

    REFRESH_RATE = 1  # SECS
    CURSES_ROW_X_OFFSET = 2
    CONNECTION_QOS = 100
    NUM_OF_COLS = 18

    def __init__(self, analyzer, summary_filename):
        BaseReporter.__init__(self)
        self.summary_filename = summary_filename

        self.analyzer = analyzer
        self.tcpstates = {}
        self.screen = self._init_screen()
        self.last_refreshed = time.time()
        self.config_subtitle = "analyzer: {0}".format(analyzer.__class__.__name__)

    def _init_screen(self):
        screen = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_WHITE)
        screen.border(0)
        return screen

    def _print_line(self, row, column, text, color=None):
        height, width = self.screen.getmaxyx()
        padding = width / CLICursesOutgoingTCPReporter.NUM_OF_COLS
        if color is not None:
            self.screen.addstr(row, CLICursesOutgoingTCPReporter.CURSES_ROW_X_OFFSET +
                                    padding*column, text.encode("utf-8"), color)
        else:
            self.screen.addstr(row, CLICursesOutgoingTCPReporter.CURSES_ROW_X_OFFSET +
                                    padding*column, text.encode("utf-8"))

    def _empty_line(self, row):
        self.screen.addstr(row, 0, "")

    def _lt_ratio_color(self, rate, min):
        return curses.color_pair(1) if rate < min else curses.color_pair(0)

    def _gt_ratio_color(self, rate, min):
        return curses.color_pair(1) if rate > min else curses.color_pair(0)

    def _est_latency_mean_color(self, mean):
        return curses.color_pair(1) if mean > 20 else curses.color_pair(0)

    def handle_remote_event(self, remote):
        self.tcpstates[remote.hostname] = remote
        # if time.time() - self.last_refreshed > CLICursesOutgoingTCPReporter.REFRESH_RATE:
        self.refresh()

    def refresh(self):
        self.screen.clear()
        self.screen.border(0)

        row = self._print_header()

        ordered_tcpstates = sorted(self.tcpstates.items(), key=lambda entry: entry[1].get_est_mean_rate())
        totals = {}
        for _, tcpstate in ordered_tcpstates:
            syn_count, syn_rate, est_count, est_rate, rst_count, row = \
                self._print_remote(tcpstate, row)
            totals['syn_count'] = totals.get('syn_count', 0) + syn_count
            totals['syn_rate'] = totals.get('syn_rate', 0) + syn_rate
            totals['est_count'] = totals.get('est_count', 0) + est_count
            totals['est_rate'] = totals.get('est_rate', 0) + est_rate
            totals['rst_count'] = totals.get('rst_count', 0) + rst_count

        row = self._print_totals(totals, row)
        self.screen.refresh()
        self.last_refreshed = time.time()

    def _print_header(self):
        row = 0
        self._print_line(row, 0, "TCP Remote TOP", color=curses.A_BOLD)
        self._print_line(row, 2, " - " + self.config_subtitle)

        row = 1
        self._print_line(row, 2, "Connections", color=curses.A_BOLD)
        self._print_line(row, 14, "Transport", color=curses.A_BOLD)
        self._print_line(row, 17, "Pcap", color=curses.A_BOLD)

        row = 3
        self._print_line(row, 0, "Host", color=curses.A_UNDERLINE)
        self._print_line(row, 2, "Syn(/s)", color=curses.A_UNDERLINE)
        self._print_line(row, 4, "Syn/Ack(%)", color=curses.A_UNDERLINE)
        self._print_line(row, 6, "Est(%)", color=curses.A_UNDERLINE)
        self._print_line(row, 8, "Rst(%)", color=curses.A_UNDERLINE)
        self._print_line(row, 9, "Fin_O(%)", color=curses.A_UNDERLINE)
        self._print_line(row, 10, "Fin_I(%)", color=curses.A_UNDERLINE)
        self._print_line(row, 11, "Est Rate", color=curses.A_UNDERLINE)
        self._print_line(row, 12, "QoS", color=curses.A_UNDERLINE)
        self._print_line(row, 13, "Lat", color=curses.A_UNDERLINE)

        self._print_line(row, 14, "Out", color=curses.A_UNDERLINE)
        self._print_line(row, 15, "In", color=curses.A_UNDERLINE)
        self._print_line(row, 16, "Rtt", color=curses.A_UNDERLINE)

        self._print_line(row, 17, "Err", color=curses.A_UNDERLINE)

        row = 4
        self._print_line(row, 2, "")
        return row + 1

    def _print_totals(self, totals, row):
        row += 1
        self._print_line(row, 0, 'Totals:', color=curses.A_BOLD)
        self._print_line(row, 2, "{0} ({1:.2f})".format(totals['syn_count'], totals['syn_rate']), color=curses.A_BOLD)
        self._print_line(row, 6, "{0} ({1:.2f})".format(totals['est_count'], totals['est_rate']), color=curses.A_BOLD)
        self._print_line(row, 8, str(totals['rst_count']), color=curses.A_BOLD)

        row += 1
        self._print_line(row, 0, "")
        return row + 1

    def _print_remote(self, remote, row):
        syn_count = remote.get_syn_count()
        syn_rate = remote.get_syn_mean_rate()
        est_count = remote.get_est_count()
        est_rate = remote.get_est_mean_rate()
        rst_count = remote.get_rst_count()
        syn_acc_ratio = ((float(remote.get_syn_ack_count()) / float(syn_count)) * 100) if syn_count else 0
        est_ratio = ((float(est_count) / float(syn_count)) * 100) if syn_count else 0
        rst_ratio = ((float(rst_count) / float(syn_count)) * 100) if syn_count else 0
        fin_in_count = remote.get_fin_in_count()
        fin_out_count = remote.get_fin_out_count()
        fin_in_ratio = ((float(fin_in_count) / float(syn_count))) * 100 if syn_count else 0
        fin_out_ratio = ((float(fin_out_count) / float(syn_count))) * 100 if syn_count else 0
        conn_mean_lat = remote.get_conn_latency_mean()
        rtt_95th = remote.get_transport_rtt_95th()
        qos_95th = remote.get_rt_per_conn_95th()

        self._print_line(row, 0, str(remote.hostname))
        self._print_line(row, 2, "{0} ({1:.2f})".format(syn_count, syn_rate))
        self._print_line(row, 4, "{0} ({1:.0f}%)".format(remote.get_syn_ack_count(), syn_acc_ratio),
                         self._lt_ratio_color(syn_acc_ratio, 90))
        self._print_line(row, 6, "{0} ({1:.0f}%)".format(est_count, est_ratio),
                         self._lt_ratio_color(est_ratio, 90))
        self._print_line(row, 8, "{0} ({1:.0f}%)".format(rst_count, rst_ratio),
                         self._gt_ratio_color(rst_ratio, 10))
        self._print_line(row, 9, "{0} ({1:.0f}%)".format(fin_out_count, fin_out_ratio))
        self._print_line(row, 10, "{0} ({1:.0f}%)".format(fin_in_count, fin_in_ratio))
        self._print_line(row, 11, "{0:.2f}".format(est_rate))
        self._print_line(row, 12, "{0}".format(qos_95th),
                         self._lt_ratio_color(qos_95th, CLICursesOutgoingTCPReporter.CONNECTION_QOS))
        self._print_line(row, 13, "{0:.2f}".format(remote.get_conn_latency_95th()),
                         self._est_latency_mean_color(conn_mean_lat))

        self._print_line(row, 14, "{0}".format(remote.get_outgoing_count()))
        self._print_line(row, 15, "{0}".format(remote.get_incoming_count()))
        self._print_line(row, 16, "{0:.2f}".format(rtt_95th),
                         self._gt_ratio_color(rtt_95th, 100))

        self._print_line(row, 17, "{0}".format(remote.get_pkt_err_count()))

        return syn_count, syn_rate, est_count, est_rate, rst_count, row + 1

    def _store_window(self):
        contents = []
        height, _ = self.screen.getmaxyx()
        for i in range(0, height):
            contents.append(self.screen.instr(i, 0))

        with open('{0}.trtop'.format(self.summary_filename), 'w+b') as output:
            output.write('\n'.join(contents))

    def start(self):
        self.analyzer.set_observer(self)

    def stop(self):
        self._store_window()
        curses.endwin()
