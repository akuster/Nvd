#
#  Copyright 2010 Armin Kuster <akuster@kama-aina.net>
#
#  This script is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2 as
#  published by the Free Software Foundation.
#
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
import os
import platform

__version__ = '7.9'
__author__ = 'Armin Kuster <akuster@kama-aina.net>'
__email__ = '<akuster@kama-aina.net>'
__copyright__ ="Copyright 2010 Armin Kuster"
__credits__ = """%s Version %s %s""" % \
(__copyright__, __version__, __author__)
__license__ = "GPL2"
__status__ = "Development"
__name__ = "nvdcve"
__url__ = 'http://www.kama-aina.net/python/nvdcve',


try:
    config_dir=("%s/.%s" % (__name__,os.environ['HOME']))
    config_file=("%s/%s.conf" % (__name__, config_dir))
except:
    pass

plat = platform.system()

if plat == 'Darwin':
    working_dir="/Users/Shared/%s" % __name__
elif plat == 'Linux' :
    working_dir="/var/cve/db/%s" % __name__
else:
    print "Un-supported os"
    sys.exit(2)

DBname = 'nvdcve.db'
data = working_dir+"/data"
cveweb = '/Users/Shared/cve'
cvetmpdata= '/tmp/cve/data'

nvdcve_modified_url = ["https://nvd.nist.gov/download/nvdcve-modified.xml"]
nvdcve_recent_url = ["https://nvd.nist.gov/download/nvdcve-recent.xml"]
nvdcve_urls = [
    "https://nvd.nist.gov/download/nvdcve-2002.xml",
    "https://nvd.nist.gov/download/nvdcve-2003.xml",
    "https://nvd.nist.gov/download/nvdcve-2004.xml",
    "https://nvd.nist.gov/download/nvdcve-2005.xml",
    "https://nvd.nist.gov/download/nvdcve-2006.xml",
    "https://nvd.nist.gov/download/nvdcve-2007.xml",
    "https://nvd.nist.gov/download/nvdcve-2008.xml",
    "https://nvd.nist.gov/download/nvdcve-2009.xml",
    "https://nvd.nist.gov/download/nvdcve-2010.xml",
    "https://nvd.nist.gov/download/nvdcve-2011.xml",
    "https://nvd.nist.gov/download/nvdcve-2012.xml",
]

# array - [db name, db datatype]

ver_db = [
    ['Cve id', 'cve_id', 'INTEGER', False],
    ['Vendor', 'vendor', 'TEXT', True],
    ['Product', 'prod', 'TEXT', True],
    ['Edition', 'edition', 'TEXT', True],
    ['Num', 'num', 'TEXT', True]
    ]

desc_db = [
    ['Source', 'source', 'TEXT', True],
    ['Desc', 'desc', 'BLOB', True]
    ]

sol_db = [
    ['Source', 'source', 'TEXT', True],
    ['Data', 'data', 'BLOB', True]
    ]

cve_db = [
    ['Seq', 'seq', 'VARCHAR(10)', True],
    ['CVSS_vector', 'CVSS_vector', 'TEXT', True],
    ['CVSS_base_score', 'CVSS_base_score', 'VARCHAR(5)', True],
    ['CVSS_exploit_subscore', 'CVSS_exploit_subscore', 'VARCHAR(5)', True],
    ['CVSS_impact_subscore', 'CVSS_impact_subscore', 'VARCHAR(5)', True],
    ['name', 'name', 'VARCHAR(14)', True],
    ['severity', 'severity', 'VARCHAR(7)', True],
    ['type', 'type', 'VARCHAR(4)', True],
    ['published', 'published', 'DATE', True],
    ['CVSS_version', 'CVSS_version', 'VARCHAR(5)', True],
    ['CVSS_score', 'CVSS_score', 'VARCHAR(5)', True],
    ['modified', 'modified', 'DATE', True],
    ['desc_id', 'desc_id', 'INTEGER', False],
    ['sol_id', 'sol_id', 'INTEGER', False],
    ['Vendor','vendor', 'TEXT', True],
    ['Product','prod', 'TEXT', True],
    ]

ref_db = [
    ['Cve id', 'cve_id', 'INTEGER', False],
    ['Source', 'source', 'TEXT', True],
    ['Patch', 'patch', 'VARCHAR(2)', True],
    ['URL', 'url', 'BLOB', True],
    ['Adv', 'adv', 'VARCHAR(2)', True],
    ['Data', 'data', 'TEXT', True],
    ]

range_db = [
    ['Cve id', 'cve_id', 'INTEGER', False],
    ['Data', 'data', 'VARCHAR(10)', True],
    ]

loss_types_db = [
    ['Cve id', 'cve_id', 'INTEGER', False],
    ['Type', 'type', 'VARCHAR(6)', True],
    ]

sec_prot_db = [
    ['Loss type id', 'loss_type_id', 'INTEGER', False],
    ['type', 'type', 'VARCHAR(6)', True],
    ['data', 'data', 'TEXT', True]
    ]

