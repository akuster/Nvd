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
import sys
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
    #working_dir="/var/cve/db/%s" % __name__
    working_dir=os.path.join(os.path.abspath(os.path.dirname(os.path.abspath(sys.argv[0]))),"db","%s"%  __name__)
else:
    print "Un-supported os"
    sys.exit(2)

data = working_dir+"/data"
cveweb = '/Users/Shared/cve'
cvetmpdata= '/tmp/cve/data'

nvdcve_modified_url = ["https://nvd.nist.gov/download/nvdcve-modified.xml"]
nvdcve_recent_url = ["https://nvd.nist.gov/download/nvdcve-recent.xml"]

# array - [Title, table name, db datatype, displable]

ver_db = [
    ['Cve id', 'cve_id', '', False],
    ['Vendor', 'vendor', 'String', True],
    ['Product', 'prod', 'String', True],
    ['Edition', 'edition', 'String', True],
    ['Num', 'num', 'String', True]
    ]

desc_db = [
    ['Source', 'source', 'String', True],
    ['Desc', 'desc', 'String', True]
    ]

sol_db = [
    ['Source', 'source', 'String', True],
    ['Data', 'data', 'String', True]
    ]

cve_db = [
    ['Seq', 'seq', 'String(10)', True],
    ['CVSS_vector', 'CVSS_vector', 'String', True],
    ['CVSS_base_score', 'CVSS_base_score', 'String(5)', True],
    ['CVSS_exploit_subscore', 'CVSS_exploit_subscore', 'String(5)', True],
    ['CVSS_impact_subscore', 'CVSS_impact_subscore', 'String(5)', True],
    ['name', 'name', 'String(14)', True],
    ['severity', 'severity', 'String(7)', True],
    ['type', 'type', 'String(4)', True],
    ['published', 'published', 'Date', True],
    ['CVSS_version', 'CVSS_version', 'String(5)', True],
    ['CVSS_score', 'CVSS_score', 'String(5)', True],
    ['modified', 'modified', 'Date', True],
    ['desc_id', 'desc_id', 'Integer', False],
    ['sol_id', 'sol_id', 'Integer', False],
    ['Vendor','vendor', 'String', True],
    ['Product','prod', 'String', True],
    ]

ref_db = [
    ['Cve id', 'cve_id', 'Integer', False],
    ['Source', 'source', 'String', True],
    ['Patch', 'patch', 'String(2)', True],
    ['URL', 'url', 'String', True],
    ['Adv', 'adv', 'String(2)', True],
    ['Data', 'data', 'String', True],
    ]

range_db = [
    ['Cve id', 'cve_id', 'Integer', False],
    ['Data', 'data', 'String(10)', True],
    ]

loss_types_db = [
    ['Cve id', 'cve_id', 'Integer', False],
    ['Type', 'type', 'String(6)', True],
    ]

sec_prot_db = [
    ['Loss type id', 'loss_type_id', 'Integer', False],
    ['type', 'type', 'String(6)', True],
    ['data', 'data', 'String', True]
    ]

