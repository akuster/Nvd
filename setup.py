#
import os
import sys
import glob
from distutils.core import setup

from Nvd import Constants

setup ( name='%s' % Constants.__name__,
        description='NVD crap',
        long_description='more crap',
        author='%s' % Constants.__author__,
        author_email='%s' % Constants.__email__,
        url='%s' % Constants.__url__,
        version='%s' % Constants.__version__,
        license='%s' % Constants.__license__,
        packages=['Nvd'],
        scripts=[os.path.join('bin', 'nvdcve')],
        data_files=[(os.path.join(os.environ['HOME'], '.nvdcve'), glob.glob("nvdcve/*.conf")),
        (os.path.join(Constants.working_dir, "data"), glob.glob("test/*.xml")),],
        classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: Python Software Foundation License',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Operating System :: Linux, Mac OS',
        'Programming Language :: Python',
        'Topic :: Software Development',
],
        )


