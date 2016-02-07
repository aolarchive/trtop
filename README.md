# TRTOP

TCP Remote Top is a pcap visualizer for outgoing connections. It allows monitoring connection/transport latencies as well
as QoS (Number of Reqs served for a single connection) for keep-alive sessions. Last, it attempts to detect kernel dropped
packets so you know whether to trust the information displayed to you.

## Yet Another Visualizer

TRTOP is not like any existing solution out there eg. tcpdump, tcpflow or their GUI counterparts see. Wireshark.

It works on the same principle of visualizing traffic, but it does so on a per destination basis. This means that all
traffic meant to a specific endpoint is captured and grouped together. On top of this grouping mechanism a layer of
statistics is added which extracts meaningful information from the capture itself, such as
timings (upper percentile ranges) and counters.

## Installing TRTOP

`pip install trtop`

## Examples

### Simple tcpdump analysis.
The very basic scenario of analysing a tcpdump capture.
Generate a 2 min network capture of **all** TCP traffic on **every** available network interface.
    
```$ tcpdump -B 8192 -i any -s 100 -w sample.pcap 'tcp'```

After 2 mins kill the command with `Ctrl-C`. In your `cwd` you should now have a capture file names *sample.pcap*. 
To visualize the capture lets use the following script *simple.py*:

```
import tempfile
import logging
logfile = tempfile.mktemp(".log", "trtop-")
    print("Logging in {0}".format(str(logfile)))

logging.basicConfig(filename=logfile, level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
from trtop import *
main(default_collector, default_analyzer, default_reporter)
```

Notice that the above simply delegates the actual work to TRTOP but you can provide logging configuration and/or extend TRTOP's functionality. 

```$ python simple.py -i sample.pcap```

### Simple tcpdump analysis with DNS resolving.

Re-using the sample from the previous section. We need to modify the *simple.py* script to include DNS resolving.

```
import socket

class SimpleResolver(BaseResolver):

    def __init__(self):
        BaseResolver.__init__(self)

    def resolve(self, addr, port):
        name, alias, addresslist = socket.gethostbyaddr(addr)
        return name

import tempfile
import logging
logfile = tempfile.mktemp(".log", "trtop-")
    print("Logging in {0}".format(str(logfile)))
    
logging.basicConfig(filename=logfile, level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
                
from trtop.resolver import BaseResolver
from trtop.analyzer import OutgoingTCPAnalyzer
from trtop.whitelisting import DefaultWhitelist
from trtop.reporter import CLICursesOutgoingTCPReporter

class SimpleResolver(BaseResolver):

    def __init__(self):
        BaseResolver.__init__(self)

    def resolve(self, addr, port):
        # Tranlate each addr to an Alphabet letter followed by the hash value.
        names = [c for c in string.ascii_uppercase]
        return names[hash(addr) % len(names)] + '_' + str(hash(addr))

from trtop import *
custom_analyzer = OutgoingTCPAnalyzer(DefaultWhitelist(), SimpleResolver())
custom_collector = TCPDumpFileCollector(custom_analyzer, dump_input_filename)
custom_reporter = CLICursesOutgoingTCPReporter(custom_analyzer, report_filename_prefix)

main(custom_collector, custom_analyzer, custom_reporter)

```

Output:

```
lqTCP Remote TOPqqqqqqqqqq - analyzer: OutgoingTCPAnalyzerqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqk
x                         Connections                                                                                                                                     Transport                           Pcap        x
x                                                                                                                                                                                                                         x
x Host                    Syn(/s)                 Syn/Ack(%)              Est(%)                  Rst(%)      Fin_O(%)    Fin_I(%)    Est Rate    QoS         Lat         Out         In          Rtt         Err         x
x                                                                                                                                                                                                                         x
x Z_1542127702888712731   2 (4.29)                1 (50%)                 0 (0%)                  0 (0%)      0 (0%)      0 (0%)      0.00        *           0.00        0           0           0.00        0           x
x G_7514259239945197122   1 (0.05)                0 (0%)                  0 (0%)                  1 (100%)    0 (0%)      0 (0%)      0.00        *           0.00        0           0           0.00        0           x
x C_6407528758213011470   1 (0.05)                1 (100%)                1 (100%)                0 (0%)      0 (0%)      0 (0%)      0.05        *           131.73      1           1           220.53      0           x
x J_1953571102544085007   1 (0.05)                1 (100%)                1 (100%)                0 (0%)      0 (0%)      0 (0%)      0.05        *           169.28      5           4           193.74      0           x
x V_-8015019010264378117  1 (0.05)                1 (100%)                1 (100%)                0 (0%)      0 (0%)      0 (0%)      0.05        *           109.72      0           0           0.00        0           x
x D_5122824042368872505   1 (0.05)                1 (100%)                1 (100%)                0 (0%)      0 (0%)      0 (0%)      0.05        *           29.03       4           4           153.48      0           x
x V_5122824042369872509   1 (0.05)                1 (100%)                1 (100%)                0 (0%)      0 (0%)      0 (0%)      0.05        *           67.62       4           4           58.22       0           x
x O_2315603488666767378   1 (0.06)                1 (100%)                1 (100%)                0 (0%)      0 (0%)      0 (0%)      0.06        *           16.18       6           7           17.95       0           x
x S_2315603488668767380   1 (0.06)                1 (100%)                1 (100%)                0 (0%)      1 (100%)    0 (0%)      0.06        4.0         38.78       6           4           26.25       0           x

```
Your resolver can be extended to fit your expectations, either for static or dynamic resolution. Similarly, you can extend/modify the whitelisting functionality.
```
class SimpleWhitelist(BaseWhitelist):

    def __init__(self):
        BaseWhitelist.__init__(self)

    def allow(self, host, port):
        return host in ['10.0.0.1', '10.0.0.2']

custom_analyzer = OutgoingTCPAnalyzer(SimpleWhitelist(), SimpleResolver())
```

This will only visualize traffic to these two destination, filtering out everything else in the capture file.
Similarly, the reporter (by default CLI curses)) can be modified/changed to fit your own needs. Simply provide an implementation for the trtop.BaseReporter interface.

## F.A.Q

* #### Can I use TRTOP for real-time capturing - visualizing ?
TRTOP is based on the use of tcpdump to read the pcap binary capture. The problem with this dependency is that once the tcpdump consumer process reaches the EOF it halts, no matter if the tcpdump producer is still writing but in a very slow pace. Thus, depending on your environment, if your producer is slower than your consumer, you will only be able to visualize a batch of the data and not all of it. Here is a useful snippet that will make that happen, if you considered the above warning and you still want to try.
```
#!/usr/bin/env bash

trap 'jobs -p | xargs kill' EXIT
trap 'deactivate' EXIT
trap 'stty sane' EXIT # Exceptions could leave the stty in bad mode

DUMP_OUT="/tmp/simple.pcap_"
tcpdump -B 8192 -i any -s 100 -w "${DUMP_OUT}" 'tcp' &
sleep 15 # buffering of traffic in dump file. allow producer a head start.
python simple.py -i ${DUMP_OUT}
```

To overcome the above issue, TRTOP has an online/active mode of capturing, which is not yet open sourced. This online mode, is using libpcap directly to capture traffic rather been depended on tcpdump.This active mode is not a silver lining either, because due to Python its not able to process traffic as fast, causing packets to be dropped from Kernel. Work is in progress to modify tcpdump itself, to allow a piped reader.

* #### Can I use TRTOP for streaming connections eg. Video streams ?
Unfortunately this functionality is not yet supported. TRTOP is mainly useful for the traditional Request/Response model, especially in re-usable connections for subsequent requests - measuring that way performance and latencies.

* #### What are the meanings of the each column of the output ?
    * **Host:** The remote endpoint as seen in the capture (or the hostname if DNS resolving is on).
    * **Syn:** Count of attempted outgoing connections. In parenthesis: Connections attempt rate per second.
    * **Syn/Ack:** Percentage of successful connection ack from the remote side. (2-way handshake)
    * **Est:** Percentage of successfully established connections. (3-way handshake)
    * **Rst:** Percentage of reset-ed connections. (Unexpectedly closed)
    * **Fin_O:** Percentage of local FIN initiated attempts.
    * **Fin_I:** Percentage of remote FIN initiated attempts.
    * **Est Rate:** Rate of successfully established connections per second.
    * **QoS:** Quality of Service - measured in terms of connection re-usability. How many requests are handled by the same     connections before it gets recycled/closed. (* means same connection for every request)
    * **Lat:** Connection latency, actual time spend to establish a valid connection
    * **Out:** Number of outgoing requests
    * **In:** Number of incoming requests
    * **Rtt:** Round Trip Time, for each individual req/resp.
    * **Err:** Internal errors detected during the capture - invalid packet sequences due to dropped packets.

    `Highlighted` entries are values that are considered high.

## Setting up dev-env

* yum install python-test
* CD in trtop root dir
* Setup a virtualenv (Python 2.7) `virtualenv env`
* Activate the newly created virtual env ` . ./env/bin/activate`
* Run `pip install -r requirements.txt`
* Run `libs/python-atomic/setup.py install`


## Components
```
                          ONLINE MODE
+---------------------------------------------------------------+
|----------------------+                 +--------------------+ |
||    PYTHON SUBPROC   |                 |  PYTHON MAIN PROC  | |
||                     |                 |                    | |
||                     |                 |                    | |               +---------------------------------------+
||   non+blocking      |    pcap pkt     |                    | |               |                 TRTOP                 |
||   pcap capture      | +-----------+   |                    | |               |                                       |
||                     | |     S     |   |                    | |               |                                       |
||         +-------->  | +---+ O +---+   |  +--------------+  | |               | +--------------+                      |
||         |           | |     C     |   |  |              |  | |               | |              |                      |
||  +------+-------+   | +---+ K +---+   |  |  Collector   +--------------+------->  Whitelist   |                      |
||  |              |   | |           |   |  |              |  | |         |     | |              |                      |
||  |  TCP STACK   |   | +---+ P +---+   |  +--------------+  | |         |     | +-------+------+                      |
||  |              |   | |     A     |   |                    | |         |     |         |                             |
||  +--------------+   | +---+ I +---+   |          ^         | |         |     |         |                             |
||                     | |     R     +--------------+         | |         |     | +-------+------+     +--------------+ |
||                     | +-----------+   |                    | |         |     | |              |     |              | |
+----------------------+                 +--------------------+ |         |     | |  Resol^er    |   +->  Reporter    | |
|                                                               |         |     | |              |   | |              | |
|                                                               |         |     | +-------+------+   | +--------------+ |
+---------------------------------------------------------------+         |     |         |          |                  |
                                                                          |     |         |          |                  |
                                                                          |     | +-------v------+   |                  |
                          OFFLINE MODE                                    |     | |              |   |                  |
+---------------------------------------------------------------+         |     | |  Analyzer    +---+                  |
|----------------------+                 +--------------------+ |         |     | |              |                      |
||   TCPDUMP -w PROC   |                 |  PYTHON MAIN PROC  | |         |     | +--------------+                      |
||                     |                 |                    | |         |     |                                       |
||                     |                 |                    | |         |     |                                       |
||                     |  +------------+ |                    | |         |     |                                       |
||                     |  |            | |                    | |         |     +---------------------------------------+
||         +-------->  |  |  pcap bin  | |                    | |         |
||         |           |  |    file    +--> +--------------+  | |         |
||  +------+-------+   |  |            | |  |              |  | |         |
||  |              |   |  +------------+ |  |  Collector   +--------------+
||  |  TCP STACK   |   |                 |  |              |  | |
||  |              |   |                 |  +--------------+  | |
||  +--------------+   |                 |                    | |
||                     |                 |                    | |
||                     |                 |                    | |
||                     |                 |                    | |
+----------------------+                 +--------------------+ |
|                                                               |
|                                                               |
+---------------------------------------------------------------+

```