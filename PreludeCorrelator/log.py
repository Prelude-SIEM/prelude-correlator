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


import logging, logging.config, logging.handlers, sys, os, siteconfig

class Log(logging.Logger):
    def __init__(self):
        try:
                logging.config.fileConfig(siteconfig.conf_dir + "/prelude-correlator.conf")
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

    def critical(self, log):
        self._logger.critical(log, extra = { "pid": os.getpid() })
