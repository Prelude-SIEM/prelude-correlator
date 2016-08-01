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

import pkg_resources
from preludecorrelator import log, error, require, plugins
import os
import imp


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


class PluginDependenciesError(ImportError):
     pass

class PluginManager(object):
    _default_entrypoint = 'preludecorrelator.plugins'

    def __init__(self, env, entrypoint=None):
        self._env = env
        self._count = 0
        self.__plugins_instances = []
        self.__plugins_classes = []

        self._conflict = {}
        self._force_enable = {}

        plugin_entries =  [ (e.name, e, self._load_entrypoint) for e in pkg_resources.iter_entry_points(entrypoint if entrypoint else self._default_entrypoint)]
        if entrypoint is None:
            plugin_entries += [ (u[0], u, self._load_userpoint ) for u in self._get_userpoints(env)]

        for pname, e, fct in plugin_entries:
            logger.debug("loading point %s", pname, level=1)

            enable_s = env.config.get(pname, "enable", default=None)
            if enable_s:
                    enable_s = enable_s.lower()

            enable = enable_s in ("true", "yes", "force", None)
            disable = env.config.getAsBool(pname, "disable", default=False)

            # do not load if the user specifically used disable=true, or enable=false
            if not enable or disable:
                logger.info("[%s]: disabled on user request", pname)
                continue

            plugin_class = fct(e)
            
            if plugin_class is None:
                continue

            if not enable_s:
                    enable = plugin_class.enable

            if enable:
                if disable:
                    enable = False

                elif enable_s == "force":
                    self._force_enable[pname] = enable

            if not enable:
                logger.info("[%s]: disabled by default", pname)
                continue

            for reason, namelist in plugin_class.conflict:
                self._conflict.update([(name, (pname, reason)) for name in namelist])

            self.__plugins_classes.append(plugin_class)

    def load(self):
        for plugin_class in self.getPluginsClassesList():
            pname = plugin_class.__name__

            if pname in self._conflict and not pname in self._force_enable:
                logger.info("[%s]: disabled by plugin '%s' reason:%s", pname, self._conflict[pname][0], self._conflict[pname][1])
                continue

            if plugin_class.autoload:
                try:
                    pi = plugin_class(self._env)

                except error.UserError as e:
                    logger.error("[%s]: %s", pname, e)
                    raise error.UserError("Plugin '%s' failed to load, please fix the issue or disable the plugin" % pname)

                self.__plugins_instances.append(pi)

            self._count += 1

    def _get_userpoints(self, env):
        if not env.config.has_section("python_rules"):
            python_rules_dirs = require.get_config_filename("rules/python")
        else:
            python_rules_dirs = env.config.get("python_rules", "paths", default="")

        for pathdir in python_rules_dirs.splitlines():
            if not os.access(pathdir, os.R_OK) or not os.path.isdir(pathdir):
                logger.warning("Can not load %s python rules dir" % pathdir)
                continue

            for f in os.listdir(pathdir):
                if not f.endswith('.py') or f == '__init__.py':
                    continue

                if os.path.isdir(os.path.join(pathdir, f)):
                    continue

                yield (f.rpartition('.')[0], pathdir)

    def _load_entrypoint(self, entrypoint):
        try:
            return entrypoint.load()

        except ImportError as e:
            logger.error("[%s]: import error: %s", entrypoint.name, e)
            return None

        except Exception as e:
            logger.exception("[%s]: loading error: %s", entrypoint.name, e)
            return None

    def _load_userpoint(self, (name, path)):
        try:
            mod_info = imp.find_module(name, [path])

        except ImportError:
            logger.warning( 'Invalid plugin "%s" in "%s"' % (name, path) )
            return None

        try:
            return getattr(imp.load_module( self._default_entrypoint + '.' + name , *mod_info), name)

        except Exception, e:
            logger.warning( "Unable to load %(file)s: %(error)s" % {'file': name,'error': str(e),})
            return None

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

            except error.UserError as e:
                logger.error("[%s]: error running plugin : %s", plugin._getName(), e)

            except Exception:
                logger.exception("[%s]: exception occurred while running", plugin._getName())
