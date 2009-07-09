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

import ConfigParser

class Config(ConfigParser.ConfigParser):
        def __init__(self, filename):
                ConfigParser.ConfigParser.__init__(self)
                self.read(filename)

        def get(self, section, option, raw=None, vars=None, default=None, type=str):
                try:
                        return type(ConfigParser.ConfigParser.get(self, section, option, raw, vars))

                except ConfigParser.NoSectionError:
                        return default

                except ConfigParser.NoOptionError:
                        return default

        def getAsBool(self, section, option, raw=None, vars=None, default=None):
                b = self.get(section, option, raw, vars, default)
                if type(b) is bool:
                        return b

                b = b.strip().lower()
                if b == "true" or b == "yes":
                        return True

                return False
