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

import PreludeEasy

class IDMEF(PreludeEasy.IDMEF):
        def __init__(self):
            self._cache = { }
            PreludeEasy.IDMEF.__init__(self)

        def Get(self, name):
            if not self._cache.has_key(name):
                self._cache[name] = PreludeEasy.IDMEF.Get(self, name)

            return self._cache[name]

        def reset(self):
                self._cache = { }

        def alert(self):
                global prelude_client
                prelude_client.correlationAlert(self)


def set_prelude_client(client):
        global prelude_client
        prelude_client = client
