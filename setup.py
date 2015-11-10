from setuptools import setup
# import versioneer


#def get_requirements():
#    requirements = []
#    with open('requirements.txt', 'r') as f:
#        for line in f.readlines():
#            requirements.append(line.strip())
#    return requirements

packages = [
    'nuagetempest',
]

package_data = {}

setup(
    name='nuage-tempest',
    version=0.1,
    # version=versioneer.get_version(),
    # cmdclass=versioneer.get_cmdclass(),
    description='Nuage Tempest tests and libraries',
    url='https://github.mv.usa.alcatel.com/pygash/nuage-tempest',
    author='Nisar',
    author_email='nisar@alcatel-lucent.com',
    license='wtfpl',
    packages=packages,
    package_data=package_data,
    include_package_data=False,
    #install_requires=get_requirements(),
    zip_safe=False
)
