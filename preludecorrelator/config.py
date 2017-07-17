# Copyright (C) 2009-2017 CS-SI. All Rights Reserved.
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

import os
import glob
import StringIO
try:
    import configparser
except:
    import ConfigParser as configparser


class Config(configparser.ConfigParser):
    def __init__(self, filename):
        configparser.ConfigParser.__init__(self, allow_no_value=True)
        self.read(filename)

        # Allow inclusion of additional configuration files in
        # prelude-correlator.conf.
        # These additional configuration files can be used by plugins.
        if self.has_section('include'):
            dataset = []
            includes = self.items('include')
            confdir = os.path.dirname(os.path.abspath(filename))

            for fpattern, _dummy in includes:
                fpattern = os.path.join(confdir, fpattern)

                # Files are loaded in alphabetical order
                for fname in sorted(glob.glob(fpattern)):
                    dataset.append(fname)

            self.read(dataset)

    def get(self, section, option, raw=None, vars=None, fallback=None, type=str):
        try:
            return type(configparser.ConfigParser.get(self, section, option, raw=raw, vars=vars))

        except configparser.NoSectionError:
            return fallback

        except configparser.NoOptionError:
            return fallback

    def getAsBool(self, section, option, raw=None, vars=None, fallback=None):
        b = self.get(section, option, raw, vars, fallback)
        if type(b) is bool:
            return b

        b = b.strip().lower()
        if b == "true" or b == "yes":
            return True

        return False

    def read(self, filename):
        if not isinstance(filename, list):
            filename = [filename]

        for fname in filename:
            try:
                f = open(fname, 'r')
            except IOError:
                continue
            self.readfp(StringIO.StringIO('[prelude]\n' + f.read()))
            f.close()
