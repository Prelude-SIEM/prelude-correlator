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

import pkg_resources
from preludecorrelator import log


logger = log.getLogger(__name__)


class Plugin(object):
    enable = True
    autoload = True
    conflict = []

    def getConfigValue(self, option, default=None, type=str):
        return self.env.config.get(self.__class__.__name__, option, default=default, type=type)

    def __init__(self, env):
        self.env = env

    def _getName(self):
        return self.__class__.__name__

    def stats(self):
        pass

    def signal(self, signo, frame):
        pass

    def run(self, idmef):
        pass


class PluginError(Exception):
     pass

class PluginManager:
    def __init__(self, env, entrypoint='preludecorrelator.plugins'):
        self._env = env
        self._count = 0
        self.__plugins_instances = []
        self.__plugins_classes = []

        conflict = {}
        force_enable = {}

        for entrypoint in pkg_resources.iter_entry_points(entrypoint):
            logger.debug("loading entry point %s", entrypoint.module_name, level=1)

            pname = entrypoint.name

            enable_s = env.config.get(pname, "enable", default=None)
            if enable_s:
                    enable_s = enable_s.lower()

            enable = enable_s in ("true", "yes", "force", None)
            disable = env.config.getAsBool(pname, "disable", default=False)

            # do not load if the user specifically used disable=true, or enable=false
            if not enable or disable:
                logger.info("[%s]: disabled on user request", pname)
                continue

            try:
                plugin_class = entrypoint.load()
            except PluginError as e:
                logger.error("[%s]: %s", pname, e)
                continue
            except Exception as e:
                logger.exception("error loading '%s': %s", pname, e)
                continue

            if not enable_s:
                    enable = plugin_class.enable

            if enable:
                if disable:
                    enable = False

                elif enable_s == "force":
                    force_enable[pname] = enable

            if not enable:
                logger.info("[%s]: disabled by default", pname)
                continue

            for reason, namelist in plugin_class.conflict:
                conflict.update([(name, (pname, reason)) for name in namelist])

            self.__plugins_classes.append(plugin_class)


        for plugin_class in self.getPluginsClassesList():
            pname = plugin_class.__name__

            if pname in conflict and not pname in force_enable:
                logger.info("[%s]: disabled by plugin '%s' reason:%s", pname, conflict[pname][0], conflict[pname][1])
                continue

            if plugin_class.autoload:
                try:
                    pi = plugin_class(env)
                except PluginError as e:
                    logger.error("[%s]: %s", pname, e)
                    continue
                except Exception:
                    logger.exception("[%s]: exception occurred while loading", pname)
                    continue

                self.__plugins_instances.append(pi)

            self._count += 1

    def getPluginCount(self):
        return self._count

    def getPluginList(self):
        return self.getPluginsInstancesList()

    def getPluginsInstancesList(self):
        return self.__plugins_instances

    def getPluginsClassesList(self):
        return self.__plugins_classes

    def stats(self):
        for plugin in self.getPluginsInstancesList():
            try:
                plugin.stats()
            except Exception:
                logger.exception("[%s]: exception occurred while retrieving statistics", plugin._getName())

    def signal(self, signo, frame):
        for plugin in self.getPluginsInstancesList():
            try:
                plugin.signal(signo, frame)
            except Exception:
                logger.exception("[%s]: exception occurred while signaling", plugin._getName())

    def run(self, idmef):
        for plugin in self.getPluginsInstancesList():
            try:
                plugin.run(idmef)
            except Exception:
                logger.exception("[%s]: exception occurred while running", plugin._getName())
