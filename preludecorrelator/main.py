#!/usr/bin/env python
#
# Copyright (C) 2009-2016 CS-SI. All Rights Reserved.
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys, os, time, signal, pkg_resources
from optparse import OptionParser, OptionGroup
from prelude import ClientEasy, checkVersion, IDMEFCriteria
from preludecorrelator import idmef, pluginmanager, context, log, config, require, error


logger = log.getLogger(__name__)
VERSION = pkg_resources.get_distribution('prelude-correlator').version
LIBPRELUDE_REQUIRED_VERSION = "0.9.25"


class Env:
    def __init__(self, options):
        self.prelude_client = None

        log.initLogger(options)
        self.config = config.Config(options.config)

        # restore previous context
        # (this need to be called after logger is setup, and before plugin loading).
        context.load(self)

        self.pluginmanager = pluginmanager.PluginManager(self)
        logger.info("%d plugins have been loaded.", self.pluginmanager.getPluginCount())


class SignalHandler:
    def __init__(self, env):
        self._env = env

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGQUIT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("caught signal %d", signum)
        self._env.pluginmanager.signal(signum, frame)

        if signum == signal.SIGQUIT:
            context.stats()
            self._env.pluginmanager.stats()

            if self._env.prelude_client:
                self._env.prelude_client.stats()
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

        self._client = ClientEasy(
            "prelude-correlator", ClientEasy.PERMISSION_IDMEF_READ|ClientEasy.PERMISSION_IDMEF_WRITE,
            "Prelude-Correlator", "Correlator", "CS-SI", VERSION)

        self._client.start()

    def _handle_event(self, idmef):
        if self._print_input:
            self._print_input.write(str(idmef))

        self._env.pluginmanager.run(idmef)
        self._events_processed += 1

    def stats(self):
        logger.info("%d events received, %d correlationAlerts generated.", self._events_processed, self._alert_generated)

    def correlationAlert(self, idmef):
        self._alert_generated = self._alert_generated + 1

        if not self._dry_run:
            self._client.sendIDMEF(idmef)

        if self._print_output:
            self._print_output.write(str(idmef))

    def _recvEventsFromClient(self, idmef):
        try:
            ret = self._client.recvIDMEF(idmef, 1000)
        except:
            ret = 0

        return ret

    def _readEventsFromFile(self, idmef, count=True):
        if count and self._env._input_limit > 0 and self._env._input_count >= self._env._input_limit:
            self._continue = 0
            return 0

        try:
            idmef << self._env._input_fd
        except EOFError:
            self._continue = 0
            return 0

        if count:
            self._env._input_count += 1

        return 1

    def _readEvents(self, _read_func_cb):
        criteria = self._env.config.get("general", "criteria")
        if criteria:
            criteria = "alert && (%s)" % (criteria)
        else:
            criteria = "alert"

        try:
            criteria = IDMEFCriteria(criteria)
        except Exception as e:
            raise error.UserError("Invalid criteria provided '%s': %s" % (criteria, e))

        last = time.time()
        while self._continue:
            msg = idmef.IDMEF()
            r = _read_func_cb(msg)

            if r:
                if criteria.match(msg):
                    self._handle_event(msg)

            now = time.time()
            if now - last >= 1:
                context.wakeup(now)
                last = now

    def readEvents(self, offset):
        for i in range(0, offset):
            self._readEventsFromFile(idmef.IDMEF(), count=False)

        self._readEvents(self._readEventsFromFile)

    def recvEvents(self):
        self._readEvents(self._recvEventsFromClient)

    def stop(self):
        self._continue = False


def runCorrelator():
    checkVersion(LIBPRELUDE_REQUIRED_VERSION)

    config_filename = require.get_config_filename("prelude-correlator.conf")

    parser = OptionParser(usage="%prog", version="%prog " + VERSION)
    parser.add_option("-c", "--config", action="store", dest="config", type="string", help="Configuration file to use", metavar="FILE", default=config_filename)
    parser.add_option("", "--dry-run", action="store_true", dest="dry_run", help="No report to the specified Manager will occur", default=False)
    parser.add_option("-d", "--daemon", action="store_true", dest="daemon", help="Run in daemon mode")
    parser.add_option("-P", "--pidfile", action="store", dest="pidfile", type="string", help="Write Prelude Correlator PID to specified file", metavar="FILE")

    grp = OptionGroup(parser, "IDMEF Input", "Read IDMEF events from file")
    grp.add_option("", "--input-file", action="store", dest="readfile", type="string", help="Read IDMEF events from the specified file", metavar="FILE")
    grp.add_option("", "--input-offset", action="store", dest="readoff", type="int", help="Start processing events starting at the given offset", metavar="OFFSET", default=0)
    grp.add_option("", "--input-limit", action="store", dest="readlimit", type="int", help="Read events until the given limit is reached", metavar="LIMIT", default=-1)
    parser.add_option_group(grp)

    parser.add_option("", "--print-input", action="store", dest="print_input", type="string", help="Dump alert input from manager to the specified file", metavar="FILE")
    parser.add_option("", "--print-output", action="store", dest="print_output", type="string", help="Dump alert output to the specified file", metavar="FILE")
    parser.add_option("-D", "--debug", action="store", dest="debug", type="int", default=0, help="Enable debugging output (level from 1 to 10)", metavar="LEVEL")
    (options, args) = parser.parse_args()

    env = Env(options)
    SignalHandler(env)

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

        os.umask(0o77)

        fd = os.open('/dev/null', os.O_RDWR)
        for i in range(3):
            os.dup2(fd, i)

        os.close(fd)
        if options.pidfile:
            open(options.pidfile, "w").write(str(os.getpid()))

    try:
        env.prelude_client = PreludeClient(env, print_input=ifd, print_output=ofd, dry_run=options.dry_run)
    except Exception as e:
        raise error.UserError(e)

    idmef.set_prelude_client(env.prelude_client)

    if options.readfile:
        env._input_limit = options.readlimit
        env._input_count = 0
        env._input_fd = open(options.readfile, "r")
        env.prelude_client.readEvents(options.readoff)
    else:
        env.prelude_client.recvEvents()

    # save existing context
    context.save()


def main():
    try:
        runCorrelator()

    except error.UserError as e:
        logger.error("error caught while starting prelude-correlator : %s", e)
        sys.exit(1)

    except:
        raise
