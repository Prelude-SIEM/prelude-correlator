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
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

try:
        import os
        from PreludeCorrelator import siteconfig

        def get_config_filename(module, fname):
                return os.path.join(siteconfig.conf_dir, fname)

        def get_data_filename(module, fname):
                return os.path.join(siteconfig.lib_dir, fname)

except:
        import pkg_resources

        def get_config_filename(module, fname):
                if module is None:
                        module = pkg_resources.Requirement.parse("prelude-correlator")

                return pkg_resources.resource_filename(module, fname)

        def get_data_filename(module, fname):
                if module is None:
                        module = pkg_resources.Requirement.parse("prelude-correlator")

                return pkg_resources.resource_filename(module, fname)

