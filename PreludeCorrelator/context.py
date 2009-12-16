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
from PreludeCorrelator.idmef import IDMEF
from PreludeCorrelator import require

_TIMER_LIST = [ ]
_CONTEXT_TABLE = { }


class Timer:
        def __setstate__(self, dict):
                self.__dict__.update(dict)
                if self._timer_start:
                        _TIMER_LIST.append(self)

        def __init__(self, expire, cb_func=None):
                self._timer_start = None
                self._timer_expire = expire
                self._timer_cb = cb_func

        def _timerExpireCallback(self):
                self.stop()
                try:
                        self._timer_cb(self)
                except:
                        pass

        def hasExpired(self, now=time.time()):
                return self.elapsed(now) >= self._timer_expire

        def check(self, now=time.time()):
                if self.hasExpired(now):
                        self._timerExpireCallback()

        def elapsed(self, now=time.time()):
                return now - self._timer_start

        def running(self):
                return self._timer_start != None

        def setExpire(self, expire):
                self._timer_expire = expire

        def start(self):
                if not self._timer_start:
                        self._timer_start = time.time()
                        _TIMER_LIST.append(self)

        def stop(self):
                if self._timer_start:
                        _TIMER_LIST.remove(self)
                        self._timer_start = None

        def reset(self):
                self.stop()
                self.start()


class Context(IDMEF, Timer):
        def __setstate__(self, dict):
                Timer.__setstate__(self, dict)
                IDMEF.__setstate__(self, dict)

        def __init__(self, name, options={}, update=False, idmef=None):
                if update and _CONTEXT_TABLE.has_key(name):
                        self._update_count += 1

                        if idmef:
                                self.addAlertReference(idmef)

                        if Timer.running(self):
                                Timer.reset(self)

                        return

                self._update_count = 0
                self._threshold = options.get("threshold", -1)
                self._alert_on_expire = options.get("alert_on_expire", False)

                self._name = name
                _CONTEXT_TABLE[name] = self

                IDMEF.__init__(self)
                Timer.__init__(self, 0)

                if idmef:
                        self.addAlertReference(idmef)

                if options.has_key("expire"):
                        Timer.setExpire(self, options["expire"])
                        Timer.start(self)

        def __new__(cls, name, options={}, update=False, idmef=None):
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
                        if callable(self._alert_on_expire):
                                self._alert_on_expire(self)
                        else:
                                self.alert()

                self.destroy()

        def getUpdateCount(self):
                return self._update_count

        def destroy(self):
                if isinstance(self, Timer):
                        self.stop()

                del(_CONTEXT_TABLE[self._name])


def search(name):
    if _CONTEXT_TABLE.has_key(name):
        return _CONTEXT_TABLE[name]

    return None


_ctxt_filename = require.get_data_filename(None, "context.dat")

def save():
        fd = open(_ctxt_filename, "w")
        pickle.dump(_CONTEXT_TABLE, fd)
        fd.close()

def load():
        if os.path.exists(_ctxt_filename):
                fd = open(_ctxt_filename, "r")
                try:
                        _CONTEXT_TABLE.update(pickle.load(fd))
                except EOFError:
                        return

def wakeup(now):
        for timer in _TIMER_LIST:
                timer.check(now)

def stats(logger):
        now = time.time()
        for ctx in _CONTEXT_TABLE.values():
                if not ctx._timer_start:
                        logger.info("[%s]: threshold=%d update=%d" % (ctx._name, ctx._threshold, ctx._update_count))
                else:
                        logger.info("[%s]: threshold=%d update=%d expire=%d" % (ctx._name, ctx._threshold, ctx._update_count, ctx._timer_expire - (now - ctx._timer_start)))
