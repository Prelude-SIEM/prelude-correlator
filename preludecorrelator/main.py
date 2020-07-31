# Copyright (C) 2009-2020 CS GROUP - France. All Rights Reserved.
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

import argparse
import sys
import os
import time
import signal
import pkg_resources
import errno
import itertools

from prelude import ClientEasy, checkVersion, IDMEFCriteria, IDMEFPath
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
        self._grouping = self._parse_path(env.config.get("general", "grouping"))

        if not options.input_file:
            self._receiver = ClientReader(self)
        else:
            self._receiver = FileReader(options.input_file, options.input_offset, options.input_limit)

        self.client = ClientEasy(
            options.profile, ClientEasy.PERMISSION_IDMEF_READ | ClientEasy.PERMISSION_IDMEF_WRITE,
            "Prelude Correlator", "Correlator", "CS GROUP", VERSION)

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

    def get_grouping(self, idmef):
        if self._grouping:
            value = idmef.get(self._grouping)
            if isinstance(value, list):
                value = value[0]
        else:
            value = None

        return self._grouping, value

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

    @staticmethod
    def _parse_path(path):
        if not path:
            return None

        try:
            IDMEFPath(path)
        except Exception as e:
            raise error.UserError("Invalid path provided '%s': %s" % (path, e))

        return path


def runCorrelator():
    checkVersion(LIBPRELUDE_REQUIRED_VERSION)
    config_filename = require.get_config_filename("prelude-correlator.conf")

    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--config", default=config_filename, metavar="FILE", help="Configuration file to use")
    parser.add_argument("--dry-run", action="store_true", help="No report to the specified Manager will occur")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run in daemon mode")
    parser.add_argument("-P", "--pidfile", metavar="FILE", help="Write Prelude Correlator PID to specified file")
    parser.add_argument("--print-input", metavar="FILE", help="Dump alert input from manager to the specified file")
    parser.add_argument("--print-output", metavar="FILE", help="Dump alert output to the specified file")
    parser.add_argument("-D", "--debug", type=int, default=0, metavar="LEVEL", nargs="?", const=1,
                        help="Enable debugging output (level from 1 to 10)")
    parser.add_argument("-v", "--version", action="version", version=VERSION)

    group = parser.add_argument_group("IDMEF Input", "Read IDMEF events from file")
    group.add_argument("--input-file", metavar="FILE", help="Read IDMEF events from the specified file")
    group.add_argument("--input-offset", type=int, default=0, metavar="OFFSET",
                       help="Start processing events starting at the given offset")
    group.add_argument("--input-limit", type=int, default=-1, metavar="LIMIT",
                       help="Read events until the given limit is reached")

    group = parser.add_argument_group("Prelude", "Prelude generic options")
    group.add_argument("--profile", default=_DEFAULT_PROFILE, help="Profile to use for this analyzer")

    options = parser.parse_args()

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
