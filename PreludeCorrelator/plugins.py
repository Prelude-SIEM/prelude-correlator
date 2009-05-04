# Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
#
# This file is part of the Prewikka program.
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

from PreludeCorrelator import siteconfig
import ConfigParser, sys, os, traceback


config = ConfigParser.ConfigParser()
config.read(siteconfig.conf_dir + '/plugins.conf')


class Plugin(object):
    enable = True

    def getConfigValue(self, key, replacement=None):
        if not config.has_section(self.__module__):
            return replacement

        try:
            return config.get(self.__module__, key)
        except ConfigParser.NoOptionError:
            return replacement

    def run(self, idmef):
        pass


class PluginManager:
    __instances = []

    def __initPlugin(self, plugin):
        p = plugin()
        if p.enable:
            self.__instances.append(p)

        self._count = self._count + 1

    def __init__(self):
        self._count = 0

        sys.path.insert(0, siteconfig.ruleset_dir)

        for file in os.listdir(siteconfig.ruleset_dir):
            pl = __import__(os.path.splitext(file)[0], None, None, [''])

        for plugin in Plugin.__subclasses__():
            self.__initPlugin(plugin)

    def getPluginCount(self):
        return self._count

    def run(self, idmef):
        for plugin in self.__instances:
            try:
                plugin.run(idmef)
            except Exception, e:
                traceback.print_exc()

