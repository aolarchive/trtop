import threading
import subprocess
import os
import signal
import logging

from collector import BaseCollector
from parser import is_valid_line, build_packet

__author__ = 'Thomas Kountis'


class TCPDumpFileCollector(BaseCollector):

    def __init__(self, analyzer, input_file_name):
        BaseCollector.__init__(self, analyzer)
        self.analyser = analyzer
        self.cap_reader_process = None
        self.input_file_name = input_file_name
        self._running = threading.Event()

    def start(self):
        logging.debug("Collector started!")
        self._start_cap_reader()
        self._running.set()
        self._collect() # takes-over main thread

    def _start_cap_reader(self):
        tcpdump_r_cmd = ["/usr/sbin/tcpdump", "-nn", "-tt", "-SU", "-r {0}".format(self.input_file_name), "2>/dev/null"]

        self.cap_reader_process = subprocess.Popen(" ".join(tcpdump_r_cmd), stdout=subprocess.PIPE,
                                                   shell=True, preexec_fn=os.setsid)

    def stop(self):
        logging.debug("Collector stopping...")
        self._running.clear()
        os.killpg(self.cap_reader_process.pid, signal.SIGTERM)
        subprocess.Popen.kill(self.cap_reader_process)
        logging.debug("Collector stopped!")

    def _collect(self):
        while self._running.is_set():
            for line in iter(lambda: self.cap_reader_process.stdout.readline(), ''):
                if not self._running.is_set():
                    break

                if is_valid_line(line):
                    self.analyser.analyse(build_packet(line))