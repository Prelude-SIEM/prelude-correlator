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

import os, time, StringIO, pickle
from PreludeCorrelator import idmef, siteconfig

_TIMER_LIST = [ ]
_CONTEXT_TABLE = { }


class Timer:
        def __setstate__(self, dict):
                self.__dict__.update(dict)
                if self._start:
                        _TIMER_LIST.append(self)

        def __init__(self, expire, cb_func=None):
                self._start = None
                self._expire = expire
                self._cb = cb_func

        def _timerExpireCallback(self):
                self.stop()
                try:
                        self._cb(self)
                except:
                        pass

        def running(self):
                return self._start != None

        def setExpire(self, expire):
                self._expire = expire

        def start(self):
                if not self._start:
                        self._start = time.time()
                        _TIMER_LIST.append(self)

        def stop(self):
                if self._start:
                        _TIMER_LIST.remove(self)
                        self._start = None

        def reset(self):
                self.stop()
                self.start()


class Context(idmef.IDMEF, Timer):
        def __setstate__(self, dict):
                Timer.__setstate__(self, dict)
                idmef.IDMEF.__setstate__(self, dict)

        def __init__(self, name, options={}, update=False):
                if update and _CONTEXT_TABLE.has_key(name):
                        if Timer.running(self):
                                Timer.reset(self)
                        return

                self._threshold = options.get("threshold", -1)
                self._alert_on_expire = options.get("alert_on_expire", False)

                self._name = name
                _CONTEXT_TABLE[name] = self

                idmef.IDMEF.__init__(self)
                Timer.__init__(self, 0)

                if options.has_key("expire"):
                        Timer.setExpire(self, options["expire"])
                        Timer.start(self)

        def __new__(cls, name, options={}, update=False):
                if update and _CONTEXT_TABLE.has_key(name):
                        return _CONTEXT_TABLE[name]

                return super(Context, cls).__new__(cls)

        def CheckAndDecThreshold(self):
                self._threshold = self._threshold - 1
                if self._threshold == 0:
                        return True
                else:
                        return False

        def _timerExpireCallback(self):
                if self._alert_on_expire:
                        self.alert()

                self.destroy()

        def destroy(self):
                if isinstance(self, Timer):
                        self.stop()

                del(_CONTEXT_TABLE[self._name])


def search(name):
    if _CONTEXT_TABLE.has_key(name):
        return _CONTEXT_TABLE[name]

    return None

def save():
        fd = open(siteconfig.lib_dir + "/context.dat", "w")
        pickle.dump(_CONTEXT_TABLE, fd)

def load():
        if os.path.exists(siteconfig.lib_dir + "/context.dat"):
                fd = open(siteconfig.lib_dir + "/context.dat", "r")
                try:
                        _CONTEXT_TABLE.update(pickle.load(fd))
                except EOFError:
                        return

def wakeup(now):
        for timer in _TIMER_LIST:
                if now - timer._start >= timer._expire:
                        timer._timerExpireCallback()


def stats():
        now = time.time()
        for ctx in _CONTEXT_TABLE.values():
                if not ctx._start:
                        print("[%s]: threshold=%d" % (ctx._name, ctx._threshold))
                else:
                        print("[%s]: threshold=%d expire=%d" % (ctx._name, ctx._threshold, ctx._expire - (now - ctx._start)))
