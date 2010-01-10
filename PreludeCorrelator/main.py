#!/usr/bin/env python
#
# Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
#
# This file is part of the Prelude-Correlator program.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

import require
import sys, os, time, signal
from optparse import OptionParser
from PreludeEasy import ClientEasy, CheckVersion
from PreludeCorrelator import __version__ as VERSION
from PreludeCorrelator import idmef, pluginmanager, context, log, config


LIBPRELUDE_REQUIRED_VERSION = "0.9.25"


class Env:
        def __init__(self, conf_filename):
                self.logger = log.Log(conf_filename)

                self.config = config.Config(conf_filename)
                self.pluginmanager = pluginmanager.PluginManager(self)

                self.logger.info("%d plugin have been loaded." % (self.pluginmanager.getPluginCount()))


class SignalHandler:
        def __init__(self, env):
                self._env = env
                signal.signal(signal.SIGTERM, self._handle_signal)
                signal.signal(signal.SIGINT, self._handle_signal)
                signal.signal(signal.SIGQUIT, self._handle_signal)

        def _handle_signal(self, signum, frame):
                self._env.logger.info("caught signal %d" % signum)
                self._env.pluginmanager.signal(signum, frame)

                if signum == signal.SIGQUIT:
                        self._env.prelude_client.stats()
                        context.stats(self._env.logger)
                else:
                        self._env.prelude_client.stop()


class PreludeClient:
        def __init__(self, env, print_input=None, print_output=None, dry_run=False):
                self._env = env
                self._events_processed = 0
                self._alert_generated = 0
                self._print_input = print_input
                self._print_output = print_output
                self._continue = True
                self._dry_run = dry_run

                self._client = ClientEasy("prelude-correlator", ClientEasy.PERMISSION_IDMEF_READ|ClientEasy.PERMISSION_IDMEF_WRITE,
                                          "Prelude-Correlator", "Correlator", "PreludeIDS Technologies",
                                          VERSION)
                self._client.Start()


        def _handle_event(self, idmef):
                if self._print_input:
                        self._print_input.write(str(idmef))

                self._env.pluginmanager.run(idmef)
                self._events_processed += 1

        def stats(self):
                self._env.logger.info("%d events received, %d correlationAlert generated." % (self._events_processed, self._alert_generated))

        def correlationAlert(self, idmef):
                self._alert_generated = self._alert_generated + 1

                if not self._dry_run:
                        self._client.SendIDMEF(idmef)

                if self._print_output:
                        self._print_output.write(str(idmef))

        def recvEvent(self):
                msg = idmef.IDMEF()

                last = time.time()
                while self._continue:
                        try:
                            r = self._client.RecvIDMEF(msg, 1000)
                        except:
                                r = 0

                        if r:
                                if msg.Get("alert.create_time"):
                                        self._handle_event(msg)
                                msg.reset()

                        now = time.time()
                        if now - last >= 1:
                                context.wakeup(now)
                                last = now

        def stop(self):
                self._continue = False


def main():
        if not CheckVersion(LIBPRELUDE_REQUIRED_VERSION):
                raise Exception, ("Libprelude version '%s' is required" % LIBPRELUDE_REQUIRED_VERSION)

        config_filename = require.get_config_filename(None, "prelude-correlator.conf")

        parser = OptionParser(usage="%prog", version="%prog " + VERSION)
        parser.add_option("-c", "--config", action="store", dest="config", type="string", help="Configuration file to use", metavar="FILE", default=config_filename)
        parser.add_option("", "--dry-run", action="store_true", dest="dry_run", help="No report to the specified Manager will occur", default=False)
        parser.add_option("-d", "--daemon", action="store_true", dest="daemon", help="Run in daemon mode")
        parser.add_option("-P", "--pidfile", action="store", dest="pidfile", type="string", help="Write Prelude Correlator PID to specified file", metavar="FILE")
        parser.add_option("", "--print-input", action="store", dest="print_input", type="string", help="Dump alert input from manager to the specified file", metavar="FILE")
        parser.add_option("", "--print-output", action="store", dest="print_output", type="string", help="Dump alert output to the specified file", metavar="FILE")
        parser.add_option("--debug", action="store", dest="debug", type="int", help="Enable debug ouptut (optional debug level argument)", metavar="LEVEL")
        (options, args) = parser.parse_args()

        env = Env(options.config)

        ifd = None
        if options.print_input:
                if options.print_input == "-":
                        ifd = sys.stdout
                else:
                        ifd = open(options.print_input, "w")

        ofd = None
        if options.print_output:
                if options.print_output == "-":
                        ofd = sys.stdout
                else:
                        ofd = open(options.print_output, "w")

        if options.daemon:
            if os.fork():
                os._exit(0)

            os.setsid()
            if os.fork():
                os._exit(0)

            os.umask(077)

            fd = os.open('/dev/null', os.O_RDWR)
            for i in xrange(3):
                os.dup2(fd, i)

            os.close(fd)
            if options.pidfile:
                open(options.pidfile, "w").write(str(os.getpid()))

        env.prelude_client = PreludeClient(env, print_input=ifd, print_output=ofd, dry_run=options.dry_run)
        idmef.set_prelude_client(env.prelude_client)

        SignalHandler(env)

        # restore previous context.
        context.load()

        env.prelude_client.recvEvent()

        # save existing context
        context.save()
