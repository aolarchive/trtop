__author__ = 'Thomas Kountis'


def timeout(func, args=(), kwargs={}, timeout_duration=1, default=None):
    """
    This function will spwan a thread and run the given function using the args, kwargs and
    return the given default value if the timeout_duration is exceeded.

    NOTE: Safer to run this in another thread, rather than in a Signal approach due to
    possible misbehavior in case an exception is raised while in wrong state (eg. finaly block).
    Last, signals are not really affecting native calls, eg. socket API
    """

    import threading

    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = default

        def run(self):
            try:
                self.result = func(*args, **kwargs)
            except:
                self.result = default

    it = InterruptableThread()
    it.start()
    it.join(timeout_duration)
    if it.isAlive():
        return it.result
    else:
        return it.result


def lookup(domain):
    import socket

    try:
        ips = timeout(func=socket.gethostbyname_ex, args=[domain], timeout_duration=1, default=([], [], []))[2]
    except socket.error:
        ips = []

    return ips


def cat(filename, default=""):
    try:
        with open(filename) as data:
            contents = data.read()
    except:
        contents = default

    return contents