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

import sys, os
from pycor import siteconfig

class Plugin(object):
    pass


class PluginManager:
        _instances = []

        def __init__(self):
                sys.path.insert(0, siteconfig.ruleset_dir)

                for file in os.listdir(siteconfig.ruleset_dir):
                        pl = __import__(os.path.splitext(file)[0], None, None, [''])

                for plugin in Plugin.__subclasses__():
                        self._instances.append(plugin())

                print "%d plugin have been loaded." % len(Plugin.__subclasses__())


        def run(self, idmef):
                for plugin in self._instances:
                        try:
                                plugin.run(idmef)
                        except Exception, e:
                                print(e)
