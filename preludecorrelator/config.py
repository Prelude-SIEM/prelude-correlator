# Copyright (C) 2009-2015 CS-SI. All Rights Reserved.
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

try:
    import configparser
except:
    import ConfigParser as configparser

class Config(configparser.ConfigParser):
        def __init__(self, filename):
                configparser.ConfigParser.__init__(self)
                self.read(filename)

        def get(self, section, option, raw=None, vars=None, default=None, type=str):
                try:
                        return type(configparser.ConfigParser.get(self, section, option, raw=raw, vars=vars))

                except configparser.NoSectionError:
                        return default

                except configparser.NoOptionError:
                        return default

        def getAsBool(self, section, option, raw=None, vars=None, default=None):
                b = self.get(section, option, raw, vars, default)
                if type(b) is bool:
                        return b

                b = b.strip().lower()
                if b == "true" or b == "yes":
                        return True

                return False
