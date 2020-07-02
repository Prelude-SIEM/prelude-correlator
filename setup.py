#!/usr/bin/env python

# Copyright (C) 2009-2019 CS-SI. All Rights Reserved.
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

from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.sdist import sdist

try:
    import urllib.request as urlreq
except:
    import urllib2 as urlreq


PRELUDE_CORRELATOR_VERSION = "5.1.2"


class my_sdist(sdist):
    user_options = sdist.user_options + [('disabledl', None, "Disable the download of databases")]
    disabledl = False

    def _downloadDatabase(self, dname, url, filename):
        print("Downloading %s database, this might take a while..." % (dname))
        req = urlreq.Request(url)
        req.add_header('User-agent', 'Mozilla 5.10')
        r = urlreq.urlopen(req)
        fd = open(filename, "w")
        fd.write(r.read())
        fd.close()

    def __init__(self, *args, **kwargs):
        fin = os.popen('git log --summary --stat --no-merges --date=short', 'r')
        fout = open('ChangeLog', 'w')
        fout.write(fin.read())
        fout.close()
        sdist.__init__(self, *args)

    def run(self):
        if self.disabledl:
            print("Automatic downloading of databases is disabled.")
            print("As a result, they won't be included in the generated source distribution.")
        else:
            self._downloadDatabase("DShield", "http://www.dshield.org/ipsascii.html?limit=10000", "rules/dshield.dat")
            self._downloadDatabase("Spamhaus", "http://www.spamhaus.org/drop/drop.lasso", "rules/spamhaus_drop.dat")
            self._downloadDatabase("CIArmy", "http://cinsscore.com/list/ci-badguys.txt", "rules/ciarmy.dat")
        sdist.run(self)


class my_install(install):
    def run(self):
        for dirname, flist in self.distribution.data_files:
            prefix = self.prefix
            if self.prefix == "/usr":
                prefix = os.sep

            destdir = os.path.join(os.path.normpath((self.root or '') + prefix), dirname)
            self.mkpath(destdir)

            for f in flist:
                dest = os.path.join(destdir, os.path.basename(f))
                if dest[-4:] == "conf" and os.path.exists(dest):
                    dest += "-dist"

                self.copy_file(f, destdir)

        self.distribution.data_files = []
        self.init_siteconfig(prefix)
        install.run(self)
        os.remove("preludecorrelator/siteconfig.py")

    def init_siteconfig(self, prefix):
        config = open("preludecorrelator/siteconfig.py", "w")
        config.write("conf_dir = '%s'\n" % os.path.abspath(prefix + "/etc/prelude-correlator"))
        config.write("lib_dir = '%s'\n" % os.path.abspath(prefix + "/var/lib/prelude-correlator"))
        config.close()


setup(
    name="prelude-correlator",
    version=PRELUDE_CORRELATOR_VERSION,
    maintainer="Prelude Team",
    maintainer_email="support.prelude@c-s.fr",
    author="Yoann Vandoorselaere",
    author_email="yoannv@gmail.com",
    license="GPL",
    url="https://www.prelude-siem.org",
    download_url="https://www.prelude-siem.org/projects/prelude/files",
    description="Prelude-Correlator perform real time correlation of events received by Prelude",
    long_description="""
Prelude-Correlator perform real time correlation of events received by Prelude.

Several isolated alerts, generated from different sensors, can thus
trigger a single CorrelationAlert should the events be related. This
CorrelationAlert then appears within the Prewikka interface and
indicates the potential target information via the set of correlation
rules.

Signature creation with Prelude-Correlator is based on the Python
programming language. Prelude's integrated correlation engine is
distributed with a default set of correlation rules, yet you still
have the opportunity to modify and create any correlation rule that
suits your needs.
""",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: System :: Monitoring"
    ],
    packages=find_packages(".", exclude=["rules"]),
    entry_points={
        'console_scripts': [
            'prelude-correlator = preludecorrelator.main:main',
        ],
        'preludecorrelator.plugins': [
        ]
    },
    package_data={},
    data_files=[
        ("etc/prelude-correlator", ["prelude-correlator.conf"]),
        ("etc/prelude-correlator/conf.d", ['data/conf.d/README']),
        ("etc/prelude-correlator/rules/python", [
            os.path.join('rules', x) for x in os.listdir('rules') if x.endswith('.py')
        ]),
        ("var/lib/prelude-correlator/prelude-correlator", [
            os.path.join('rules', x) for x in os.listdir('rules') if x.endswith('.dat')
        ])
    ],
    install_requires=["prelude >= 5.1.0"],
    cmdclass={
        'sdist': my_sdist,
        'install': my_install
    }
)
