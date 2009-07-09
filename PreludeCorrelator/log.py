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
            self.warnings(("[unknown:%d] " % level) + log)

    def __init__(self, conf_filename):
        try:
                PreludeEasy.PreludeLog.SetCallback(self.__log_callback)
        except:
                # PreludeLog is available in recent libprelude version, we do not want to fail if it's not.
                pass

        try:
                logging.config.fileConfig(conf_filename)
        except Exception, e:
                DATEFMT = "%d %b %H:%M:%S"
                FORMAT="%(asctime)s (process:%(pid)d) %(levelname)s: %(message)s"
                logging.basicConfig(level=logging.DEBUG, format=FORMAT, datefmt=DATEFMT, stream=sys.stderr)

        self._logger = logging.getLogger("prelude-correlator")

    def debug(self, log):
        self._logger.debug(log, extra = { "pid": os.getpid() })

    def info(self, log):
        self._logger.info(log, extra = { "pid": os.getpid() })

    def warning(self, log):
        self._logger.warning(log, extra = { "pid": os.getpid() })

    def error(self, log):
        self._logger.error(log, extra = { "pid": os.getpid() })

    def critical(self, log):
        self._logger.critical(log, extra = { "pid": os.getpid() })
