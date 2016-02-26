# -*- coding: utf-8 -*-
# dispatcher.py
# Copyright (C) 2016 LEAP
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
Command dispatcher.
"""
from twisted.internet import defer
from twisted.python import failure


# TODO implement sub-classes to dispatch subcommands (user, mail).


class CommandDispatcher(object):

    def __init__(self, core):

        self.core = core

    def _get_service(self, name):

        try:
            return self.core.getServiceNamed(name)
        except KeyError:
            return None

    def dispatch(self, msg):
        cmd = msg[0]

        _method = getattr(self, 'do_' + cmd.upper(), None)

        if not _method:
            return defer.fail(failure.Failure(RuntimeError('No such command')))

        return defer.maybeDeferred(_method, *msg)

    def do_STATS(self, *parts):
        return self.core.do_stats()

    def do_VERSION(self, *parts):
        return self.core.do_version()

    def do_STATUS(self, *parts):
        return self.core.do_status()

    def do_SHUTDOWN(self, *parts):
        print "Service Stopped. Have a nice day."
        self.core.do_shutdown()

    def do_USER(self, *parts):

        subcmd = parts[1]
        user, password = parts[2], parts[3]

        bf = self._get_service('bonafide')

        if subcmd == 'authenticate':
            print 'authenticating...'
            d = bf.do_authenticate(user, password)

        elif subcmd == 'signup':
            d = bf.do_signup(user, password)

        elif subcmd == 'logout':
            d = bf.do_logout(user, password)

        elif subcmd == 'active':
            d = bf.do_get_active_user()

        return d

    def do_EIP(self, *parts):
        subcmd = parts[1]
        eip_label = 'eip'

        if subcmd == 'enable':
            return self.core.do_enable_service(eip_label)

        eip = self._get_service(eip_label)
        if not eip:
            return 'eip: disabled'

        if subcmd == 'status':
            return eip.do_status()

        elif subcmd == 'disable':
            return self.core.do_disable_service(eip_label)

        elif subcmd == 'start':
            # TODO --- attempt to get active provider
            provider = parts[2]
            return eip.do_start(provider)

        elif subcmd == 'stop':
            return eip.do_stop()

    def do_MAIL(self, *parts):
        subcmd = parts[1]
        mail_label = 'mail'

        if subcmd == 'enable':
            return self.core.do_enable_service(mail_label)

        m = self._get_service(mail_label)
        bf = self._get_service('bonafide')

        if not m:
            return 'mail: disabled'

        if subcmd == 'status':
            return m.do_status()

        elif subcmd == 'disable':
            return self.core.do_disable_service(mail_label)

        elif subcmd == 'get_imap_token':
            return m.get_imap_token()

        elif subcmd == 'get_smtp_token':
            return m.get_smtp_token()

        elif subcmd == 'get_smtp_certificate':
            # TODO move to mail service
            # TODO should ask for confirmation? like --force or something,
            # if we already have a valid one. or better just refuse if cert
            # exists.
            # TODO how should we pass the userid??
            # - Keep an 'active' user in bonafide (last authenticated)
            # (doing it now)
            # - Get active user from Mail Service (maybe preferred?)
            # - Have a command/method to set 'active' user.

            @defer.inlineCallbacks
            def save_cert(cert_data):
                userid, cert_str = cert_data
                cert_path = yield m.do_get_smtp_cert_path(userid)
                with open(cert_path, 'w') as outf:
                    outf.write(cert_str)
                defer.returnValue('certificate saved to %s' % cert_path)

            d = bf.do_get_smtp_cert()
            d.addCallback(save_cert)
            return d
