#!/usr/bin/env python
# -*- coding: utf-8 -*-
# bitmask_cli
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
Bitmask Command Line interface: zmq client.
"""
import sys
import getpass
import argparse


from colorama import init as color_init
from colorama import Fore
from twisted.internet import reactor
from txzmq import ZmqEndpoint, ZmqFactory, ZmqREQConnection
import zmq

from leap.bonafide import config


class BitmaskCLI(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='''bitmask_cli <command> [<args>]

Controls the Bitmask application.

SERVICE COMMANDS:

   user       Handles Bitmask accounts
   mail       Bitmask Encrypted Mail
   eip        Encrypted Internet Proxy

GENERAL COMMANDS:

   version    prints version number and exit
   shutdown   shutdown Bitmask backend daemon
   status     displays general status about the running Bitmask services
   debug      show some debug info about bitmask-core


''', epilog=("Use 'bitmask_cli <command> --help' to learn more "
             "about each command."))
        parser.add_argument('command', help='Subcommand to run')

        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        self.args = args
        self.subargs = None

        if not hasattr(self, args.command):
            print 'Unrecognized command'
            parser.print_help()
            exit(1)

        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def user(self):
        parser = argparse.ArgumentParser(
            description=('Handles Bitmask accounts: creation, authentication '
                         'and modification'),
            prog='bitmask_cli user')
        parser.add_argument('--create', action='store_true',
                            help='register a new user, if possible')
        parser.add_argument('--authenticate', action='store_true',
                            help='logs in against the provider')
        parser.add_argument('--logout', action='store_true',
                            help='ends any active session with the provider')
        parser.add_argument('username',
                            help='username ID, in the form <user@example.org>')
        # now that we're inside a subcommand, ignore the first
        # TWO argvs, ie the command (bitmask_cli) and the subcommand (user)
        args = parser.parse_args(sys.argv[2:])
        self.subargs = args

    def mail(self):
        parser = argparse.ArgumentParser(
            description='Bitmask Encrypted Mail service',
            prog='bitmask_cli mail')
        parser.add_argument('--start', action='store_true',
                            help='tries to start the mail service')
        parser.add_argument('--stop', action='store_true',
                            help='stops the mail service if running')
        parser.add_argument('--status', action='store_true',
                            help='displays status about the mail service')
        parser.add_argument('--enable', action='store_true')
        parser.add_argument('--disable', action='store_true')
        parser.add_argument('--get-imap-token', action='store_true',
                            help='returns token for the IMAP service')
        parser.add_argument('--get-smtp-token', action='store_true',
                            help='returns token for the SMTP service')
        parser.add_argument('--get-smtp-certificate', action='store_true',
                            help='downloads a new smtp certificate')
        parser.add_argument('--check-smtp-certificate', action='store_true',
                            help='downloads a new smtp certificate '
                            '(NOT IMPLEMENTED)')

        args = parser.parse_args(sys.argv[2:])
        self.subargs = args

    def eip(self):
        parser = argparse.ArgumentParser(
            description='Encrypted Internet Proxy service',
            prog='bitmask_cli eip')
        parser.add_argument('--start', action='store_true',
                            help='Start service')
        parser.add_argument('--stop', action='store_true', help='Stop service')
        parser.add_argument('--status', action='store_true',
                            help='Display status about service')
        parser.add_argument('--enable', action='store_true')
        parser.add_argument('--disable', action='store_true')
        args = parser.parse_args(sys.argv[2:])
        self.subargs = args

    # Single commands

    def shutdown(self):
        pass

    def status(self):
        pass

    def version(self):
        pass

    def debug(self):
        pass


def get_zmq_connection():
    zf = ZmqFactory()
    e = ZmqEndpoint('connect', config.ENDPOINT)
    return ZmqREQConnection(zf, e)


def error(msg, stop=False):
    print Fore.RED + "[!] %s" % msg + Fore.RESET
    if stop:
        reactor.stop()
    else:
        sys.exit(1)


def do_print(stuff):
    print Fore.GREEN + stuff[0] + Fore.RESET


def send_command(cli):

    args = cli.args
    subargs = cli.subargs
    cb = do_print

    cmd = args.command

    if cmd == 'version':
        do_print(['bitmask_cli: 0.0.1'])
        data = ("version",)

    elif cmd == 'status':
        data = ("status",)

    elif cmd == 'shutdown':
        data = ("shutdown",)

    elif cmd == 'debug':
        data = ("stats",)

    elif cmd == 'user':
        username = subargs.username
        if '@' not in username:
            error("Username ID must be in the form <user@example.org>",
                  stop=True)
            return

        # TODO check that ONLY ONE FLAG is True
        # TODO check that AT LEAST ONE FLAG is True

        passwd = getpass.getpass()

        if subargs.create:
            data = ("user", "signup", username, passwd)
        if subargs.authenticate:
            data = ("user", "authenticate", username, passwd)
        if subargs.logout:
            data = ("user", "logout", username, passwd)

    elif cmd == 'mail':
        if subargs.status:
            data = ("mail", "status")

        if subargs.get_imap_token:
            data = ("mail", "get_imap_token")

        if subargs.get_smtp_token:
            data = ("mail", "get_smtp_token")

        if subargs.get_smtp_certificate:
            data = ("mail", "get_smtp_certificate")

    elif cmd == 'eip':
        if subargs.start:
            data = ("eip", "start")

        if subargs.stop:
            data = ("eip", "stop")

    s = get_zmq_connection()
    try:
        d = s.sendMsg(*data)
    except zmq.error.Again:
        print Fore.RED + "[ERROR] Server is down" + Fore.RESET
    d.addCallback(cb)
    d.addCallback(lambda x: reactor.stop())


def main():
    color_init()
    cli = BitmaskCLI()
    reactor.callWhenRunning(reactor.callLater, 0, send_command, cli)
    reactor.run()

if __name__ == "__main__":
    main()
