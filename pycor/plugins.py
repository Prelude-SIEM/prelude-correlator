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

class Plugin(object):
    pass

class PluginManager:
        _instances = []

        def __init__(self):
                path = "/home/yoann/dev/prelude/git/pycor/ruleset"
                sys.path.insert(0, path)

                for file in os.listdir(path):
                        pl = __import__(os.path.splitext(file)[0], None, None, [''])

                for plugin in Plugin.__subclasses__():
                        self._instances.append(plugin())

        def find(self):
                return self._instances

