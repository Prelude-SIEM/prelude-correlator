# Copyright (C) 2014-2017 CS-SI. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoannv@gmail.com>
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
    import urllib.request as urlreq
except:
    import urllib2 as urlreq

import os
import time

from preludecorrelator import error
from preludecorrelator.context import Timer

class DownloadCache:
    def _checkPermissions(self):
        dirname = os.path.dirname(self._filename)

        if not os.access(dirname, os.R_OK|os.W_OK|os.X_OK):
            raise error.UserError("DownloadCache directory '%s' does not exist or has wrong permissions" % (dirname))

        if os.path.exists(self._filename) and not os.access(self._filename, os.R_OK|os.W_OK):
            raise error.UserError("DownloadCache file '%s' cannot be opened in read-write mode" % (self._filename))

    def __init__(self, name, filename, reload, logger, bindata=False):
        self._name = name
        self._filename = filename
        self._reload = reload
        self._data = None
        self.logger = logger
        self._bindata = bindata

        self._checkPermissions()

        age = self._doInit()
        if self._reload > 0:
            Timer(self._reload - age, self._download).start()

    def _doInit(self):
        age = False
        try:
            st = os.stat(self._filename)
            age = time.time() - st.st_mtime

            # If the data didn't expire, we're good to go
            if self._reload <= 0 or age < self._reload:
                self._load(age)
                return age

        except OSError:
            pass

        try:
            self._download()
        except Exception:
            # There was an error downloading newer data, use any older data that we have, even if it's expired
            # If we don't have any older data available, then this is an error, and there is no fallback.
            if not age:
                raise Exception("%s data couldn't be retrieved, and no previous data available" % self._name)
            self._load(age)

        return 0

    def _download(self, timer=None):
        status ="Downloading" if not timer else "Updating"
        self.logger.info("%s %s report, this might take some time...", status, self._name)

        try:
            unparsed_data = self.download()
            self.__data = self.parse(unparsed_data)

            fd = open(self._filename, "wb" if self._bindata else "w")
            self.write(fd, unparsed_data)
            fd.close()

            self.logger.info("%s %s report done.", status, self._name)
        except Exception as e:
            self.logger.error("error %s %s report : %s", status.lower(), self._name, e)
            if not timer:
                raise

        if timer:
            timer.setExpire(self._reload)
            timer.reset()

    def _load(self, age):
        self.__data = self.parse(self.read(open(self._filename, "rb" if self._bindata else "r")))
        self.logger.info("Loaded %s data from a previous run (age=%.2f hours)", self._name, age / 60 / 60)

    def download(self):
        pass

    def parse(self, data):
        return data

    def get(self):
        return self.__data


class HTTPDownloadCache(DownloadCache):
    def __init__(self, name, filename, uri, timeout, reload, logger, bindata=False):
        self.__uri = uri
        self.__timeout = timeout
        DownloadCache.__init__(self, name, filename, reload, logger, bindata)

    def read(self, fd):
        return fd.read()

    def write(self, fd, data):
        fd.write(data)

    def download(self,headers=None):
        if headers == None:
            headers={'User-Agent' : "Prelude-Correlator"}

        con = urlreq.urlopen(urlreq.Request(self.__uri, headers=headers))
        data = con.read()

        if not self._bindata:
            _mime_type, _sep, encoding = con.headers['content-type'].partition('charset=')
            data = data.decode(encoding or 'ascii')

        return data
