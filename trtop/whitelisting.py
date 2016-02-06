__author__ = 'Thomas Kountis'


class BaseWhitelist(object):

    def __init__(self):
        pass

    def allow(self, host, port):
        pass


class DefaultWhitelist(BaseWhitelist):

    def __init__(self):
        BaseWhitelist.__init__(self)

    def allow(self, host, port):
        return True


class StaticListWhitelist(BaseWhitelist):

    def __init__(self, allowed):
        BaseWhitelist.__init__(self)
        self.allowed = allowed

    def allow(self, host, port):
        return host in self.allowed





