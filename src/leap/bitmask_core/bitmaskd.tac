# Service composition for bitmask-core.
# Run as: twistd -n -y bitmaskd.tac
#
from twisted.application import service

from leap.bonafide.zmq_service import BonafideZMQService
from leap.bitmask_core import mail_services

top_service = service.MultiService()

bonafide_zmq_service = BonafideZMQService()
bonafide_zmq_service.setServiceParent(top_service)
bonafide_zmq_service.register_hook('on_bonafide_auth', 'soledad')

soledad_service = mail_services.SoledadService()
soledad_service.setName("soledad")
soledad_service.setServiceParent(top_service)
soledad_service.register_hook('on_new_soledad_instance', 'keymanager')

keymanager_service = mail_services.KeymanagerService()
keymanager_service.setName("keymanager")
keymanager_service.setServiceParent(top_service)
keymanager_service.register_hook('on_new_keymanager_instance', 'mail')

mail_service = mail_services.MailService()
mail_service.setName("mail")
mail_service.setServiceParent(top_service)

application = service.Application("bitmaskd")
top_service.setServiceParent(application)
