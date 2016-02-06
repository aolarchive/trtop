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
                
custom_analyzer = OutgoingTCPAnalyzer(DefaultWhitelist(), SimpleResolver())

from trtop import *
main(default_collector, custom_analyzer, default_reporter)
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

## F.A.Q

* #### Can I use TRTOP for streaming connections eg. Video streams
Unfortunately this functionality is not yet supported. TRTOP is mainly useful for the traditional Request/Response model, especially in re-usable connections for subsequent requests - measuring that way performance and latencies.

* #### What are the meanings of the each column of the output.
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