# Copyright (C) 2018-2020 CS-SI. All Rights Reserved.
# Author: Antoine Luong <antoine.luong@c-s.fr>
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


class AbstractRule(object):
    depends = []

    def _can_correlate(self, idmef):
        """
        Return a boolean indicating if a rule is allowed to correlate an alert.
        """
        if idmef.get("alert.analyzer(0).model") != "Prelude Correlator":
            return True

        ruleid = idmef.get("alert.additional_data('Rule ID').data")
        return ruleid and ruleid[0] in self.depends
