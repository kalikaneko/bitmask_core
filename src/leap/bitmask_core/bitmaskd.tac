# Service composition for bitmask-core.
# Run as: twistd -n -y bitmaskd.tac
#
from twisted.application import service

from leap.bitmask_core.service import BitmaskBackend


bb = BitmaskBackend()
application = service.Application("bitmaskd")
bb.setServiceParent(application)
