__author__ = 'Thomas Kountis'


class BaseResolver(object):

    def __init__(self):
        pass

    def resolve_async(self, addr, port, callback):
        raise RuntimeError("Async resolve not supported")

    def resolve(self, addr, port):
        raise RuntimeError("Sync resolve not supported")


class DefaultDNSResolver(BaseResolver):

    def __init__(self):
        BaseResolver.__init__(self)

    def resolve_async(self, addr, port, callback):
        callback(addr, self.resolve(addr, port))

    def resolve(self, addr, port):
        return addr


class NoResolver(BaseResolver):

    def __init__(self):
        BaseResolver.__init__(self)

    def resolve_async(self, addr, port, callback):
        callback(addr, addr)
