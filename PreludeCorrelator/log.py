# Copyright (C) 2009-2012 CS-SI. All Rights Reserved.
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

import PreludeEasy
import logging, logging.config, logging.handlers, sys, os

class Log(logging.Logger):
    def __log_callback(self, level, log):
        log = log.rstrip('\n')

        if level == PreludeEasy.PreludeLog.DEBUG:
            self.debug(log)

        elif level == PreludeEasy.PreludeLog.INFO:
            self.info(log)

        elif level == PreludeEasy.PreludeLog.WARNING:
            self.warning(log)

        elif level == PreludeEasy.PreludeLog.ERROR:
            self.error(log)

        elif level == PreludeEasy.PreludeLog.CRITICAL:
            self.critical(log)

        else:
            self.warning(("[unknown:%d] " % level) + log)

    def __init__(self, options):
        self.debug_level = options.debug

        try:
                PreludeEasy.PreludeLog.SetCallback(self.__log_callback)
        except:
                # PreludeLog is available in recent libprelude version, we do not want to fail if it's not.
                pass

        self._have_extra = sys.version_info > (2, 4)

        try:
                logging.config.fileConfig(options.config)
        except Exception, e:
                DATEFMT = "%d %b %H:%M:%S"
                if not self._have_extra:
                        FORMAT="%(asctime)s %(name)s %(levelname)s: %(message)s"
                else:
                        FORMAT="%(asctime)s %(name)s (process:%(pid)d) %(levelname)s: %(message)s"

                logging.basicConfig(level=logging.DEBUG, format=FORMAT, datefmt=DATEFMT, stream=sys.stderr)

        self._logger = logging.getLogger("prelude-correlator")

        if options.daemon is True:
                hdlr = logging.handlers.SysLogHandler('/dev/log')
                hdlr.setFormatter(logging.Formatter('%(name)s: %(levelname)s: %(message)s'))
                self._logger.addHandler(hdlr)

    def _log(self, log_func, log, extra):
        if self._have_extra:
                log_func(log, extra=extra)
        else:
                log_func(log)

    def debug(self, log, level=0):
        if level >= self.debug_level:
            self._log(self._logger.debug, log, extra = { "pid": os.getpid() })

    def info(self, log):
        self._log(self._logger.info, log, extra = { "pid": os.getpid() })

    def warning(self, log):
        self._log(self._logger.warning, log, extra = { "pid": os.getpid() })

    def error(self, log):
        self._log(self._logger.error, log, extra = { "pid": os.getpid() })

    def critical(self, log):
        self._log(self._logger.critical, log, extra = { "pid": os.getpid() })
