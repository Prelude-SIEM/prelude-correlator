# Copyright (C) 2009-2018 CS-SI. All Rights Reserved.
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

import sys
import os
import time
import signal
import pkg_resources
import errno
import itertools

from optparse import OptionParser, OptionGroup
from prelude import ClientEasy, checkVersion, IDMEFCriteria
from preludecorrelator import idmef, pluginmanager, context, log, config, require, error


if sys.version_info >= (3, 0):
    import builtins
else:
    import __builtin__ as builtins


logger = log.getLogger(__name__)
VERSION = pkg_resources.get_distribution('prelude-correlator').version
LIBPRELUDE_REQUIRED_VERSION = "1.2.6"
_DEFAULT_PROFILE = "prelude-correlator"


def _init_profile_dir(profile):
    filename = require.get_data_filename("context.dat", profile=profile)

    try:
        os.makedirs(os.path.dirname(filename), mode=0o700)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


class Env:
    def __init__(self, options):
        self.prelude_client = None

        log.initLogger(options)
        self.config = config.Config(options.config)
        self.profile = options.profile

    def load_plugins(self):
        self.pluginmanager = pluginmanager.PluginManager()

        # restore previous context
        # (this need to be called after logger is setup, and before plugin loading).
        context.load(self.profile)

        # Since we can launch different instances of prelude-correlator with different profiles,
        # we need to separate their context and specific rules data files
        # (this need to be called before plugin loading)
        _init_profile_dir(self.profile)

        self.pluginmanager.load()
        self.pluginmanager.check_dependencies()
        logger.info("%d plugins have been loaded.", self.pluginmanager.getPluginCount())


class SignalHandler:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGQUIT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("caught signal %d", signum)
        env.pluginmanager.signal(signum, frame)

        if signum == signal.SIGUSR1:
            context.save(env.profile)
            env.pluginmanager.save()

        elif signum == signal.SIGQUIT:
            context.stats()
            env.pluginmanager.stats()

            if env.prelude_client:
                env.prelude_client.stats()

        else:
            env.prelude_client.stop()


class GenericReader(object):
    _messages = iter([])

    def run(self):
        pass

    def inject(self, idmef):
        self._messages = itertools.chain(self._messages, [idmef])


class ClientReader(GenericReader):
    def __init__(self, prelude_client):
        self.prelude_client = prelude_client

    def run(self):
        while True:
            for msg in self._messages:
                yield msg

            msg = idmef.IDMEF()
            try:
                ret = self.prelude_client.client.recvIDMEF(msg, 1000)
            except Exception:
                ret = None

            if ret:
                yield msg
            else:
                yield None


class FileReader(GenericReader):
    def __init__(self, filename, offset=0, limit=-1):
        self.filename = filename
        self.offset = offset
        self.limit = limit

    def run(self):
        count = 0

        with open(self.filename, 'r') as input_file:
            while self.limit == -1 or count < self.limit + self.offset:
                for msg in self._messages:
                    yield msg

                msg = idmef.IDMEF()
                try:
                    msg << input_file
                except EOFError:
                    break

                count += 1

                if count >= self.offset:
                    yield msg


class PreludeClient(object):
    def __init__(self, options, print_input=None, print_output=None, dry_run=False):
        self._events_processed = 0
        self._alert_generated = 0
        self._print_input = print_input
        self._print_output = print_output
        self._continue = True
        self._dry_run = dry_run
        self._criteria = self._parse_criteria(env.config.get("general", "criteria"))

        if not options.readfile:
            self._receiver = ClientReader(self)
        else:
            self._receiver = FileReader(options.readfile, options.readoff, options.readlimit)

        self.client = ClientEasy(
            options.profile, ClientEasy.PERMISSION_IDMEF_READ | ClientEasy.PERMISSION_IDMEF_WRITE,
            "Prelude Correlator", "Correlator", "CS-SI", VERSION)

        self.client.setConfigFilename(options.config)
        self.client.start()

    def _handle_event(self, idmef):
        if self._print_input:
            self._print_input.write(str(idmef))

        env.pluginmanager.run(idmef)
        self._events_processed += 1

    def stats(self):
        logger.info("%d events received, %d correlationAlerts generated.",
                    self._events_processed,
                    self._alert_generated)

    def correlationAlert(self, idmef):
        self._alert_generated = self._alert_generated + 1

        if not self._dry_run:
            self.client.sendIDMEF(idmef)

        if self._print_output:
            self._print_output.write(str(idmef))

        # Reinject correlation alerts for meta-correlation
        self._receiver.inject(idmef)

    def run(self):
        last = time.time()
        for msg in self._receiver.run():
            if msg and self._criteria.match(msg):
                self._handle_event(msg)

            now = time.time()
            if now - last >= 1:
                context.wakeup(now)
                last = now

            if not self._continue:
                break

    def stop(self):
        self._continue = False

    @staticmethod
    def _parse_criteria(criteria):
        if not criteria:
            return IDMEFCriteria("alert")

        criteria = "alert && (%s)" % criteria

        try:
            return IDMEFCriteria(criteria)
        except Exception as e:
            raise error.UserError("Invalid criteria provided '%s': %s" % (criteria, e))


def runCorrelator():
    checkVersion(LIBPRELUDE_REQUIRED_VERSION)
    config_filename = require.get_config_filename("prelude-correlator.conf")

    parser = OptionParser(usage="%prog", version="%prog " + VERSION)
    parser.add_option("-c", "--config", action="store", dest="config", type="string", help="Configuration file to use",
                      metavar="FILE", default=config_filename)
    parser.add_option("", "--dry-run", action="store_true", dest="dry_run",
                      help="No report to the specified Manager will occur", default=False)
    parser.add_option("-d", "--daemon", action="store_true", dest="daemon", help="Run in daemon mode")
    parser.add_option("-P", "--pidfile", action="store", dest="pidfile", type="string",
                      help="Write Prelude Correlator PID to specified file", metavar="FILE")

    grp = OptionGroup(parser, "IDMEF Input", "Read IDMEF events from file")
    grp.add_option("", "--input-file", action="store", dest="readfile", type="string",
                   help="Read IDMEF events from the specified file", metavar="FILE")
    grp.add_option("", "--input-offset", action="store", dest="readoff", type="int",
                   help="Start processing events starting at the given offset", metavar="OFFSET", default=0)
    grp.add_option("", "--input-limit", action="store", dest="readlimit", type="int",
                   help="Read events until the given limit is reached", metavar="LIMIT", default=-1)
    parser.add_option_group(grp)

    grp = OptionGroup(parser, "Prelude", "Prelude generic options")
    grp.add_option("", "--profile", dest="profile", type="string", help="Profile to use for this analyzer",
                   default=_DEFAULT_PROFILE)
    parser.add_option_group(grp)

    parser.add_option("", "--print-input", action="store", dest="print_input", type="string",
                      help="Dump alert input from manager to the specified file", metavar="FILE")
    parser.add_option("", "--print-output", action="store", dest="print_output", type="string",
                      help="Dump alert output to the specified file", metavar="FILE")
    parser.add_option("-D", "--debug", action="store", dest="debug", type="int", default=0,
                      help="Enable debugging output (level from 1 to 10)", metavar="LEVEL")
    (options, args) = parser.parse_args()

    builtins.env = Env(options)
    env.load_plugins()
    SignalHandler()

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
        env.prelude_client = PreludeClient(options, print_input=ifd, print_output=ofd)
    except Exception as e:
        raise error.UserError(e)

    idmef.set_prelude_client(env.prelude_client)

    env.prelude_client.run()

    # save existing context
    context.save(options.profile)
    env.pluginmanager.save()


def main():
    try:
        runCorrelator()

    except error.UserError as e:
        logger.error("error caught while starting prelude-correlator : %s", e)
        sys.exit(1)

    except:
        raise
