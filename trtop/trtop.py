import argparse
import imp
import time
import signal
import logging
import os

from functools import partial
from whitelisting import DefaultWhitelist
from analyzer import OutgoingTCPAnalyzer
from resolver import DefaultDNSResolver
from reporter import CLICursesOutgoingTCPReporter
from tcpdump.offlinecollector import TCPDumpFileCollector


__author__ = 'Thomas Kountis'
#######################################################
# TCP Remote TOP utility for *nix systems             #
#######################################################


DEFAULT_SNAPSHOT_PERIOD = 2  # Minutes

parser = argparse.ArgumentParser(description='TCP Remote TOP')
parser.add_argument('-o', '--out', help='Filename prefix for the generated report file(s). (default: time.time())')
parser.add_argument('-i', '--input', help='Filename of pcap file to analyze. Offline mode.')
parser.add_argument('-if', '--interface', help='The network interface to attach to. (default: first found ethernet IF)')
parser.add_argument('-bpf', '--bpf_filter', help='The BSD Packet Filter for libpcap to filter out unwanted traffic.')

parser.add_argument('-am', '--analyzer_module', help='The analyzer builder module, a module available in the path '
                                                     'containing a function "build()" that creates and returns an '
                                                     'instance of analyzer.BaseAnalyzer (default: OutgoingTCPAnalyzer)')

parser.add_argument('-cm', '--collector_module', help='The collector builder module, a module available in the path '
                                                      'containing a function "build()" that creates and returns an '
                                                      'instance of collector.BaseCollector '
                                                      '(default: TCPDumpExecCollector)')

parser.add_argument('-rm', '--reporter_module', help='The reporter builder module, a module available in the path '
                                                     'containing a function "build()" that creates and returns an '
                                                     'instance of reporter.BaseReporter '
                                                     '(default: CLICursesOutgoingTCPReporter)')

parser.add_argument('-wm', '--whitelist_module', help='The whitelist builder module, a module available in the path '
                                                      'containing a function "build()" that creates and returns an '
                                                      'instance of whitelist.BaseWhitelist (default: DefaultWhitelist)')

parser.add_argument('-tm', '--resolver_module', help='The resolver builder module, a module available in the path '
                                                     'containing a function "build()" that creates and returns an '
                                                     'instance of resolver.BaseResolver (default: DefaultDNSResolver)')

#TODO add whitelist option csv
#TODO add no-resolve option, use ip
#TODO add support for --mode
parser.add_argument('-m', '--mode', choices=["continuous", "snapshot"],
                    help='The collection mode, continuous or snapshot. '
                         'In continuous mode trtop will collect statistics until user interruption. '
                         'In snapshot mode trtop will collect statistics for {0} minutes and exit with a report.'
                    .format(DEFAULT_SNAPSHOT_PERIOD))

args = parser.parse_args()
loaded_modules = []


def build_or_default(name, default):
    if name:
        logging.info("Loading module {0}...".format(name))
        fp, pathname, description = imp.find_module(name)
        loaded_module = imp.load_module(name, fp, pathname, description)
        loaded_modules.append(loaded_module)
        return loaded_module.build()
    else:
        return default()

report_filename_prefix = args.out if args.out else "{0}".format(str(int(time.time())))
dump_input_filename = args.input if args.input else None
interface = args.interface
bpf_filter = args.bpf_filter

default_whitelist = build_or_default(args.whitelist_module, lambda: DefaultWhitelist())
default_resolver = build_or_default(args.resolver_module, lambda: DefaultDNSResolver())
default_analyzer = build_or_default(args.analyzer_module,
                                    lambda: OutgoingTCPAnalyzer(default_whitelist, default_resolver))
default_collector = build_or_default(args.collector_module,
                                         lambda: TCPDumpFileCollector(default_analyzer, dump_input_filename))

default_reporter = build_or_default(args.reporter_module,
                                    lambda: CLICursesOutgoingTCPReporter(default_analyzer, report_filename_prefix))


def _clean_up_modules():
    for module in loaded_modules:
        logging.info("Cleaning module: {0}... ".format(module))
        module.clean_up()
        logging.info("CLEANED!")


def _stop_trtop(collector, analyzer, reporter):
    logging.info("TRTOP session finished!")
    collector.stop()
    reporter.stop()
    _clean_up_modules()
    os._exit(0) # TODO without force it hangs here, investigate if the main thread is still blocked


def _signal_handler(collector, analyzer, reporter, signal, frame):
    logging.info("Caught SIGINT, exiting...")
    _stop_trtop(collector, analyzer, reporter)


def main(collector, analyzer, reporter):
    logging.info("New TRTOP session with: {0}".format(str((collector, analyzer, reporter))))
    signal.signal(signal.SIGINT, partial(_signal_handler, collector, analyzer, reporter))

    reporter.start()
    collector.start()

if __name__ == "__main__":
    main(default_collector, default_analyzer, default_reporter)
