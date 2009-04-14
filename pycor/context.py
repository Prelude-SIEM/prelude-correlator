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

from threading import Timer
from pycor import idmef

_CONTEXT_TABLE = {}

class Context(idmef.IDMEF):
        def __init__(self, name, options={}, update=False):
                if update and _CONTEXT_TABLE.has_key(name):
                        #_CONTEXT_TABLE[name]._timer.cancel()
                        #_CONTEXT_TABLE[name]._timer.start()
                        self = _CONTEXT_TABLE[name]

                self._name = name
                self._threshold = options.get("threshold", -1)
                self._alert_on_expire = options.get("alert_on_expire", False)

                if options.has_key("expire"):
                        #self._timer = Timer(options["expire"], self._timer_expire)
                        #self._timer.start()
                        pass

                _CONTEXT_TABLE[name] = self

        def _timer_expire(self):
                _CONTEXT_TABLE[self._name] = None
                del(self)

        def update(self, name, options={}):
                pass


def get_context(name):
        return _CONTEXT_TABLE.get(name, None)
