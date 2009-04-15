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

import time, StringIO, pickle
from pycor import idmef, siteconfig

_TIMER_LIST = [ ]
_CONTEXT_TABLE = { }


class Timer:
        def __setstate__(self, dict):
                self.__dict__.update(dict)
                if self._active:
                        _TIMER_LIST.append(self)

        def __del__(self):
                try:
                        self.stop()
                except:
                        return

        def __init__(self, expire, ctxname):
                self._active = False
                self._expire = expire
                self._ctxname = ctxname
                self.start()

        def stop(self):
                if self._active:
                        _TIMER_LIST.remove(self)
                        self._active = False

        def start(self):
                self._active = True
                self._start = time.time()
                _TIMER_LIST.append(self)

        def reset(self):
                self.stop()
                self.start()

        def expire(self):
                self.stop()
                _CONTEXT_TABLE[self._ctxname].destroy(expire=True)


class Context(idmef.IDMEF):
        def __init__(self, name, options={}, update=False):

                if update and _CONTEXT_TABLE.has_key(name):
                        ctx = _CONTEXT_TABLE[name]
                        if ctx._timer:
                                ctx._timer.reset()

                self._name = name
                self._threshold = options.get("threshold", -1)
                self._alert_on_expire = options.get("alert_on_expire", False)

                if options.has_key("expire"):
                        self._timer = Timer(options["expire"], self._name)
                else:
                        self._timer = None

                _CONTEXT_TABLE[name] = self
                idmef.IDMEF.__init__(self)

        def __new__(cls, name, options={}, update=False):
                if update and _CONTEXT_TABLE.has_key(name):
                        return _CONTEXT_TABLE[name]

                return super(Context, cls).__new__(cls, name, options, update)


        def CheckAndDecThreshold(self):
                self._threshold = self._threshold - 1
                if self._threshold == 0:
                        return True
                else:
                        return False

        def destroy(self, expire=False):
                if self._timer:
                        self._timer.stop()

                if expire and self._alert_on_expire:
                        self.alert()

                del(_CONTEXT_TABLE[self._name])


def search(name):
    if _CONTEXT_TABLE.has_key(name):
        return _CONTEXT_TABLE[name]

    return None

def save():
        fd = open(siteconfig.lib_dir + "/context.dat", "w")
        pickle.dump(_CONTEXT_TABLE, fd)

def load():
        fd = open(siteconfig.lib_dir + "/context.dat", "r")
        _CONTEXT_TABLE.update(pickle.load(fd))

def wakeup(now):
        for timer in _TIMER_LIST:
                if now - timer._start >= timer._expire:
                        timer.expire()
