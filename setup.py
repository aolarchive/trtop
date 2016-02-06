from setuptools import setup

setup(
    name='trtop',
    version='0.1.1',
    packages=['trtop', 'trtop/tcpdump'],
    install_requires=[
        "AppMetrics==0.5.0",
        "argparse==1.2.1"
    ],
    url='',
    license='MIT License',
    platforms='Linux',
    author='Thomas Kountis',
    author_email='tkountis@gmail.com',
    keywords=['tcpdump', 'trtop', 'pcap'],
    description='TCP Remote Top is a tcpdump log visualizer for outgoing connections. '
                'It allows monitoring connection/transport latencies as well as QoS (Number of Reqs served '
                'for a single connection) for keep-alive sessions. Last, it attempts to detect kernel dropped '
                'packets so you know whether to trust the information displayed to you. '
)
