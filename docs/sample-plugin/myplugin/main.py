from preludecorrelator.pluginmanager import Plugin


class MyPlugin(Plugin):
    def run(self, idmef):
        print("Hello from %s" % self.__class__.__name__)
        print(idmef)
