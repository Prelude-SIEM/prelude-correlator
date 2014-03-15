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

import pkg_resources, sys, os, traceback, ConfigParser


class PluginLog:
    def __init__(self, env):
        self.__logger = env.logger
        self.__prefix = "[" + self.__class__.__name__ + "]: "

    def debug(self, log):
        self.__logger.debug(self.__prefix + log)

    def info(self, log):
        self.__logger.info(self.__prefix + log)

    def warning(self, log):
        self.__logger.warning(self.__prefix + log)

    def error(self, log):
        self.__logger.error(self.__prefix + log)

    def critical(self, log):
        self.__logger.critical(self.__prefix + log)


class Plugin(object, PluginLog):
    enable = True

    def getConfigValue(self, option, default=None, type=str):
        return self.env.config.get(self.__class__.__name__, option, default=default, type=type)

    def __init__(self, env):
        self.env = env
        PluginLog.__init__(self, env)

    def _getName(self):
        return self.__class__.__name__

    def stats(self):
        pass

    def signal(self, signo, frame):
        pass

    def run(self, idmef):
        pass


class PluginManager:
    def __init__(self, env, entrypoint='PreludeCorrelator.plugins'):
        self._env = env
        self._count = 0
        self.__instances = []

        for entrypoint in pkg_resources.iter_entry_points(entrypoint):
            env.logger.debug("loading entry point %s" % entrypoint, 1)

            try:
                plugin_class = entrypoint.load()
            except Exception, e:
                env.logger.warning("%s: %s" % (entrypoint, e))
                continue

            pname = plugin_class.__name__

            if env.config.getAsBool(pname, "disable", default=False) is True:
                env.logger.info("[%s]: disabled on user request" % (pname))
                continue

            try:
                pi = plugin_class(env)
            except Exception, e:
                env.logger.error("[%s]: exception occurred while loading:\n%s" % (pname, traceback.format_exc()))
                continue

            self.__instances.append(pi)
            self._count += 1

    def getPluginCount(self):
        return self._count

    def getPluginList(self):
        return self.__instances

    def stats(self):
        for plugin in self.__instances:
            try:
                plugin.stats()
            except Exception, e:
                self._env.logger.error("[%s]: exception occurred while retrieving statistics:\n%s" % (plugin._getName(), traceback.format_exc()))

    def signal(self, signo, frame):
        for plugin in self.__instances:
            try:
                plugin.signal(signo, frame)
            except Exception, e:
                self._env.logger.error("[%s]: exception occurred while signaling:\n%s" % (plugin._getName(), traceback.format_exc()))

    def run(self, idmef):
        for plugin in self.__instances:
            try:
                plugin.run(idmef)
            except Exception, e:
                self._env.logger.error("[%s]: exception occurred while running:\n%s" % (plugin._getName(), traceback.format_exc()))
