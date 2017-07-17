from setuptools import setup, find_packages


setup(
    name='MyPlugin',
    version='1.0',
    description="Plugin description",
    author="Foo Bar",
    packages=find_packages(),
    entry_points='''
        [preludecorrelator.plugins]
        MyPlugin = myplugin:MyPlugin
    '''
)
