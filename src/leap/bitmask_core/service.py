# -*- coding: utf-8 -*-
# service.py
# Copyright (C) 2015 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Bitmask-core Service.
"""
import resource

from twisted.internet import reactor
from twisted.python import log

from leap.bonafide.service import BonafideService

from leap.bitmask_core import configurable
from leap.bitmask_core import mail_services
from leap.bitmask_core import _zmq
from leap.bitmask_core import websocket
from leap.bitmask_core._version import get_versions

from leap.common.events import server as event_server
from leap.vpn import EIPService


class BitmaskBackend(configurable.ConfigurableService):

    def __init__(self, basedir='~/.config/leap'):

        configurable.ConfigurableService.__init__(self, basedir)

        def enabled(service):
            return self.get_config('services', service, False, boolean=True)

        self.init_events()
        self.init_bonafide()

        if enabled('mail'):
            self.init_soledad()
            self.init_keymanager()
            self.init_mail()

        if enabled('eip'):
            self.init_eip()

        if enabled('zmq'):
            self.init_zmq()

        if enabled('web'):
            self.init_web()

    def init_events(self):
        event_server.ensure_server()

    def init_bonafide(self):
        bf = BonafideService(self.basedir)
        bf.setName("bonafide")
        bf.setServiceParent(self)
        bf.register_hook('on_passphrase_entry', trigger='soledad')
        bf.register_hook('on_bonafide_auth', trigger='soledad')

    def init_soledad(self):
        sol = mail_services.SoledadService(self.basedir)
        sol.setName("soledad")
        sol.setServiceParent(self)
        sol.register_hook('on_new_soledad_instance', trigger='keymanager')

    def init_keymanager(self):
        km = mail_services.KeymanagerService(self.basedir)
        km.setName("keymanager")
        km.setServiceParent(self)
        km.register_hook('on_new_keymanager_instance', trigger='mail')

    def init_mail(self):
        ms = mail_services.StandardMailService(self.basedir)
        ms.setName("mail")
        ms.setServiceParent(self)

    def init_eip(self):
        eip_service = EIPService()
        eip_service.setName("eip")
        eip_service.setServiceParent(self)

    def init_zmq(self):
        zs = _zmq.ZMQDispatcher(self)
        zs.setServiceParent(self)

    def init_web(self):
        ws = websocket.WebSocketsDispatcherService(self)
        ws.setServiceParent(self)

    # General commands for the BitmaskBackend Core Service

    def do_stats(self):
        log.msg('BitmaskCore Service STATS')
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return '[+] BitmaskCore: [Mem usage: %s KB]' % (mem / 1024)

    def do_status(self):
        # we may want to make this tuple a class member
        services = ('soledad', 'keymanager', 'mail', 'eip')

        status_messages = []
        for name in services:
            status = "stopped"
            if self.getServiceNamed(name).running:
                status = "running"
            status_messages.append("[{}: {}]".format(name, status))

        return " ".join(status_messages)

    def do_version(self):
        version = get_versions()['version']
        return "BitmaskCore: %s" % version

    def do_shutdown(self):
        self.stopService()
        reactor.stop()

    def do_eip_start(self):
        eip = self.getServiceNamed('eip')
        eip.do_start()

    def do_eip_stop(self):
        eip = self.getServiceNamed('eip')
        eip.do_stop()
