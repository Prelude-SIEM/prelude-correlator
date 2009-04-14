#!/usr/bin/env python

import os, glob
from distutils.command.install import install
from distutils.core import setup

PYCOR_VERSION = "0.1"

class my_install(install):
        def run(self):
                if self.prefix:
                        self.conf_prefix = self.prefix + "/etc/pycor"
                else:
                        self.conf_prefix = "/etc/pycor"

                if not os.path.exists(self.prefix + "/var/lib/pycor"):
                        os.makedirs(self.prefix + "/var/lib/pycor")
                        
                self.init_siteconfig()
                install.run(self)
                
        def init_siteconfig(self):
                config = open("pycor/siteconfig.py", "w")
                print >> config, "conf_dir = '%s'" % os.path.abspath(self.conf_prefix)
                print >> config, "ruleset_dir = '%s'" % os.path.abspath(self.conf_prefix + "/ruleset")
                print >> config, "lib_dir = '%s'" % os.path.abspath(self.prefix + "/var/lib/pycor")
                print >> config, "version = '%s'" % PYCOR_VERSION
                config.close()

setup(name="pycor",
      version=PYCOR_VERSION,
      maintainer = "Yoann Vandoorselaere",
      maintainer_email = "yoann.v@prelude-ids.com",
      url = "http://www.prelude-ids.com",
      packages=[ 'pycor'],
      data_files=[('etc/pycor/ruleset', glob.glob("ruleset/*.py"))],
      scripts=[ "scripts/pycor" ],
      cmdclass={ 'install': my_install })
