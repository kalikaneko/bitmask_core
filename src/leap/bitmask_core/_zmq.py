# -*- coding: utf-8 -*-
# _zmq.py
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
ZMQ REQ-REP Dispatcher.
"""

from twisted.application import service
from twisted.internet import reactor
from twisted.python import log

from txzmq import ZmqEndpoint, ZmqFactory, ZmqREPConnection

from leap.bonafide import config


class ZMQDispatcher(service.Service):

    def __init__(self, core):
        self._core = core

    def startService(self):
        zf = ZmqFactory()
        e = ZmqEndpoint("bind", config.ENDPOINT)

        self._conn = _DispatcherREPConnection(zf, e, self._core)
        reactor.callWhenRunning(self._conn.do_greet)
        service.Service.startService(self)

    def stopService(self):
        service.Service.stopService(self)


class _DispatcherREPConnection(ZmqREPConnection):

    # XXX this should inherit from a common dispatcher,
    # or receive a generic dispatcher instance

    def __init__(self, zf, e, core):
        ZmqREPConnection.__init__(self, zf, e)
        self.core = core

    def gotMessage(self, msgId, *parts):

        cmd = parts[0]

        if cmd == 'stats':
            r = self.core.do_stats()
            self.defer_reply(r, msgId)

        if cmd == 'status':
            r = self.core.do_status()
            self.defer_reply(r, msgId)

        if cmd == 'version':
            r = self.core.do_version()
            self.defer_reply(r, msgId)

        if cmd == 'shutdown':
            r = 'ok, shutting down...'
            self.defer_reply(r, msgId)
            self.do_shutdown()

        if cmd == 'user':
            subcmd = parts[1]
            user, password = parts[2], parts[3]

            bf = self._get_service('bonafide')

            if subcmd == 'authenticate':
                d = bf.do_authenticate(user, password)
            if subcmd == 'signup':
                d = bf.do_signup(user, password)
            if subcmd == 'logout':
                d = bf.do_logout(user, password)
            d.addCallback(lambda r: self.defer_reply(r, msgId))
            d.addErrback(lambda f: self.log_err(f, msgId))

        if cmd == 'mail':
            subcmd = parts[1]

            m = self._get_service('mail')

            if subcmd == 'status':
                r = m.do_status()
                self.defer_reply(r, msgId)

            if subcmd == 'get_imap_token':
                d = m.get_imap_token()
                d.addCallback(lambda r: self.defer_reply(r, msgId))
                d.addErrback(lambda f: self.log_err(f, msgId))

        if cmd == 'eip':
            subcmd = parts[1]

            eip = self._get_service('eip')

    def _get_service(self, name):
        return self.core.getServiceNamed(name)

    def defer_reply(self, response, msgId):
        reactor.callLater(0, self.reply, msgId, str(response))

    def log_err(self, failure, msgId):
        log.err(failure)
        self.defer_reply("ERROR: %r" % failure, msgId)

    def do_greet(self):
        print "Starting ZMQ Dispatcher"

    def do_shutdown(self):
        print "Service Stopped. Have a nice day."
        self.core.do_shutdown()
