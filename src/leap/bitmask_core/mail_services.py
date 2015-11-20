"""
Mail services.

This is quite moving work still. This could be moved to the different packages
when it stabilizes.
"""
import os
from collections import defaultdict

from twisted.application import service
from twisted.python import log

from leap.keymanager import KeyManager
from leap.soledad.client.api import Soledad
from leap.mail.imap.service import imap


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
    the hook. On that service, the method "activate_hook" will be called.

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

        this_hook = 'on_new_soledad_instance'
        hooked_service = self.service.get_hooked_service(this_hook)
        if hooked_service:
            hooked_service.activate_hook(
                this_hook,
                user=userid, uuid=uuid, token=token,
                soledad=soledad)

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

    # TODO move activate_hook to a dispatcher pattern + class attribute

    def startService(self):
        print "Starting Soledad Service"
        self._container = SoledadContainer()
        self._container.service = self

    def activate_hook(self, kind, **kw):
        if kind == 'on_bonafide_auth':
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
            hooked_service.activate_hook(
                this_hook,
                userid=userid,
                soledad=soledad)

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

    # TODO move activate_hook to a dispatcher pattern + class attribute

    def startService(self):
        print "Starting Keymanager Service"
        self._container = KeymanagerContainer()
        self._container.service = self

    def activate_hook(self, kind, **kw):
        if kind == 'on_new_soledad_instance':
            container = self._container
            user = kw['user']
            token = kw['token']
            uuid = ['uuid']
            soledad = kw['soledad']
            if not container.get_instance(user):
                container.add_instance(user, token, uuid, soledad)


class MailService(service.Service, HookableService):

    # TODO move activate_hook to a dispatcher pattern + class attribute
    # TODO factor out Mail Service to inside mail package.

    def startService(self):
        print "Starting Mail Service..."

    def activate_hook(self, kind, **kw):
        # XXX we can specify this as a waterfall, or just AND the two
        # conditions.
        if kind == 'on_new_keymanager_instance':
            print "STARTING MAIL SERVICE"
            soledad = kw['soledad']
            user = kw['userid']
            imap.run_service(soledad, userid=user)
