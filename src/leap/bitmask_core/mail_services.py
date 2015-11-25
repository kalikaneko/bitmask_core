"""
Mail services.

This is quite moving work still.
This should be moved to the different packages when it stabilizes.
"""
import os
from collections import defaultdict

from twisted.application import service
from twisted.python import log

from leap.keymanager import KeyManager
from leap.soledad.client.api import Soledad
from leap.mail.constants import INBOX_NAME
from leap.mail.imap.service import imap
from leap.mail.incoming.service import IncomingMail, INCOMING_CHECK_PERIOD
from leap.mail.smtp import setup_smtp_gateway


class Container(object):

    def __init__(self):
        self._instances = defaultdict(None)

    def get_instance(self, key):
        return self._instances.get(key, None)


class HookableService(object):

    """
    This service allows for other services to be notified
    whenever a certain kind of hook happens.

    During the service composition, one is expected to register
    a kind of hook with the service that wants to react to the triggering of
    the hook. On that service, the method "notify_hook" will be called,
    which will be in turn dispatched to the method "hook_<name>".

    This is a simplistic implementation for a PoC, we probably will move
    this to another mechanism like leap.common.events, callbacks etc.
    """

    def register_hook(self, kind, service):
        if not hasattr(self, 'service_hooks'):
            self.service_hooks = {}
        log.msg("Registering hook %s->%s" % (kind, service))
        self.service_hooks[kind] = service

    def get_sibling_service(self, kind):
        return self.parent.getServiceNamed(kind)

    def get_hooked_service(self, kind):
        hooks = self.service_hooks
        if kind in hooks:
            return self.get_sibling_service(hooks[kind])

    def notify_hook(self, kind, **kw):
        if kind not in self.subscribed_to_hooks:
            raise RuntimeError(
                "Tried to notify a hook this class is not "
                "subscribed to" % self.__class__)
        getattr(self, 'hook_' + kind)(**kw)


class SoledadContainer(Container):

    def add_instance(self, userid, token, uuid):
        user, provider = userid.split('@')

        # TODO automate bootstrapping stuff
        # TODO consolidate canonical factory
        soledad = self._create_soledad_instance(
            uuid, 'lalalala', '/tmp/soledad',
            'https://goldeneye.cdev.bitmask.net:2323',
            os.path.expanduser(
                '~/.config/leap/providers/%s/keys/ca/cacert.pem' % provider),
            token)
        print "ADDING SOLEDAD INSTANCE FOR", userid
        self._instances[userid] = soledad

        # TODO --- factor out signal_hooked_service(*args, **kw)
        this_hook = 'on_new_soledad_instance'
        hooked_service = self.service.get_hooked_service(this_hook)
        if hooked_service:
            hooked_service.notify_hook(
                this_hook,
                user=userid, uuid=uuid, token=token,
                soledad=soledad)
        # TODO --- factor out

    def set_syncable(self, user, state):
        pass

    def sync(self, user):
        self.get_instance(user).sync()

    def _create_soledad_instance(self, uuid, passphrase, basedir, server_url,
                                 cert_file, token):
        # setup soledad info
        secrets_path = os.path.join(
            basedir, '%s.secret' % uuid)
        local_db_path = os.path.join(
            basedir, '%s.db' % uuid)

        # instantiate soledad
        return Soledad(
            uuid,
            unicode(passphrase),
            secrets_path=secrets_path,
            local_db_path=local_db_path,
            server_url=server_url,
            cert_file=cert_file,
            auth_token=token,
            defer_encryption=True)

class SoledadService(service.Service, HookableService):

    subscribed_to_hooks = ('on_bonafide_auth', )

    def startService(self):
        print "Starting Soledad Service"
        self._container = SoledadContainer()
        self._container.service = self
        super(SoledadService, self).startService()

    def hook_on_bonafide_auth(self, **kw):
        user = kw['username']
        uuid = kw['uuid']
        token = kw['token']
        container = self._container
        if not container.get_instance(user):
            print "Going to instantiate a new soledad %s %s %s" % (
                user, token, uuid)
            container.add_instance(user, token, uuid)


class KeymanagerContainer(Container):

    # TODO this should replace code in soledadbootstrapper

    def add_instance(self, userid, token, uuid, soledad):

        # TODO automate bootstrapping stuff
        # TODO consolidate canonical factory

        keymanager = self._create_keymanager_instance(
            userid, token, uuid, soledad)
        # TODO add hook for KEY GENERATION AND SENDING...
        print "ADD KEYMANAGER INSTANCE FOR", userid
        self._instances[userid] = keymanager

        # TODO use onready-deferreds instead

        this_hook = 'on_new_keymanager_instance'
        hooked_service = self.service.get_hooked_service(this_hook)
        if hooked_service:
            hooked_service.notify_hook(
                this_hook,
                userid=userid,
                soledad=soledad,
                keymanager=keymanager)

    def _create_keymanager_instance(self, userid, token, uuid, soledad):
        user, provider = userid.split('@')

        nickserver_uri = "https://nicknym.%s:6425" % provider
        api_uri = "https://api.%s:4430" % provider

        cert_file = os.path.expanduser(
            '~/.config/leap/providers/%s/keys/ca/cacert.pem' % provider)

        km_args = (userid, nickserver_uri, soledad)
        km_kwargs = {
            "token": token,
            "uid": uuid,
            "api_uri": api_uri,
            "api_version": "1",
            "ca_cert_path": cert_file,
            "gpgbinary": "/usr/bin/gpg"
        }
        keymanager = KeyManager(*km_args, **km_kwargs)
        return keymanager


class KeymanagerService(service.Service, HookableService):

    subscribed_to_hooks = ('on_new_soledad_instance',)

    def startService(self):
        print "Starting Keymanager Service"
        self._container = KeymanagerContainer()
        self._container.service = self
        super(KeymanagerService, self).startService()

    def hook_on_new_soledad_instance(self, **kw):
        container = self._container
        user = kw['user']
        token = kw['token']
        uuid = ['uuid']
        soledad = kw['soledad']
        if not container.get_instance(user):
            container.add_instance(user, token, uuid, soledad)



class MailAccountContainer(Container):

    def add_instance(self, userid, soledad, keymanager):
        pass


class StandardMailService(service.MultiService, HookableService):
    """
    A collection of Services.

    This is the parent service, that launches 3 different services that expose
    Encrypted Mail Capabilities on specific ports:

        - SMTP service, on port 2013
        - IMAP service, on port 1984
        - The IncomingMail Service, which doesn't listen on any port, but
          watches and processes the Incoming Queue and saves the processed mail
          into the matching INBOX.
    """

    # TODO factor out Mail Service to inside mail package.

    subscribed_to_hooks = ('on_new_keymanager_instance',)

    def initializeChildrenServices(self):
        self.addService(IMAPService())
        self.addService(SMTPService())
        self.addService(IncomingMailService())

    def startService(self):
        print "Starting Mail Service..."
        self._container = MailAccountContainer()
        self._container.service = self
        super(StandardMailService, self).startService()

    def stopService(self):
        super(StandardMailService, self).stopService()

    def hook_on_new_keymanager_instance(self, **kw):
        # XXX we can specify this as a waterfall, or just AND the two
        # conditions.
        soledad = kw['soledad']
        keymanager = kw['keymanager']
        userid = kw['userid']

        imap = self.getServiceNamed('imap')
        imap.startInstance(soledad, userid)

        smtp = self.getServiceNamed('smtp')
        smtp.startInstance(keymanager, userid)


class IMAPService(service.Service):

    name = 'imap'

    # TODO --- this needs to allow authentication,
    # to be able to expose the SAME service for different
    # accounts.

    # TODO -- the offline service (ie, until BONAFIDE REMOTE
    # has been authenticated) should expose a dummy IMAP account.

    def __init__(self):
        self._instances = {}

    def startService(self):
        print "Starting dummy IMAP Service"
        super(IMAPService, self).startService()

    def stopService(self):
        # TODO cleanup all instances
        super(IMAPService, self).stopService()

    # Individual accounts

    def startInstance(self, soledad, userid):
        port, factory = imap.run_service(soledad, userid=userid)
        self._instances[userid] = port, factory

    def stopInstance(self, userid):
        port, factory = self._instances[userid]
        port.stopListening()
        factory.doStop()


class SMTPService(service.Service):

    name = 'smtp'

    # TODO --- this needs to allow authentication,
    # to be able to expose the SAME service for different
    # accounts.

    # TODO -- the offline service (ie, until BONAFIDE REMOTE
    # has been authenticated) should expose a dummy SMTP account.
    def __init__(self):
        self._instances = {}

    def startService(self):
        print "Starting dummy SMTP Service"
        super(SMTPService, self).startService()

    def stopService(self):
        # TODO cleanup all instances
        super(SMTPService, self).stopService()

    # Individual accounts

    def startInstance(self, keymanager, userid):
        # TODO automate bootstrapping stuff
        # TODO consolidate canonical factory
        user, provider = userid.split('@')
        host = 'cowbird.cdev.bitmask.net'
        remote_port = 465
        client_cert_path = os.path.expanduser(
            '~/.config/leap/providers/dev.bitmask.net/'
            'keys/client/stmp_%s.pem' % user)
        service, port = setup_smtp_gateway(
            port=2013,
            userid=userid,
            keymanager=keymanager,
            smtp_host=host,
            smtp_port=remote_port,
            smtp_cert=unicode(client_cert_path),
            smtp_key=unicode(client_cert_path),
            encrypted_only=False)
        self._instances[userid] = service, port

    def stopInstance(self, userid):
        port, factory = self._instances[userid]
        port.stopListening()
        factory.doStop()


class IncomingMailService(service.Service):

    name = 'incoming_mail'

    def startService(self):
        print "Starting dummy IncomingMail Service"
        super(IncomingMailService, self).startService()

    def stopService(self):
        super(IncomingMailService, self).stopService()

    def _start_incoming_mail_service(self, keymanager, soledad,
                                     imap_factory, userid):

        def setUpIncomingMail(inbox):
            incoming_mail = IncomingMail(
                keymanager,
                soledad,
                inbox.collection,
                userid,
                check_period=INCOMING_CHECK_PERIOD)
            return incoming_mail

        acc = imap_factory.theAccount
        d = acc.callWhenReady(lambda _: acc.getMailbox(INBOX_NAME))
        d.addCallback(setUpIncomingMail)
        return d
