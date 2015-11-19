# Service composition for bitmask-core.
# Run as: twistd -n -y bitmaskd.tac
#
from twisted.application import service
from leap.bonafide.zmq_service import BonafideZMQService
from leap.bitmask_core.soledad_service import SoledadService

top_service = service.MultiService()
bonafide_zmq_service = BonafideZMQService()
bonafide_zmq_service.setServiceParent(top_service)

soledad_service = SoledadService()
soledad_service.setName("soledad")
soledad_service.setServiceParent(top_service)

application = service.Application("bitmaskd")
top_service.setServiceParent(application)
