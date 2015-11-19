"""
Soledad service.
"""
# TODO move to soledad itself?

from twisted.application import service


class SoledadService(service.Service):

    def startService(self):
        print "Starting SOLEDAD Service"
