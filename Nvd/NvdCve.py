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
import CustomParser
from NvdCveXml import NvdCveXml
from NvdCveDb import NvdCveDb
import Constants
from webify import webify_cve

class NvdCve(NvdCveXml, NvdCveDb):

    def __init__(self, debug, config_file=None):
        self.debug = debug
        self.order = []
        self.config = None
        NvdCveXml.__init__(self, debug)
        NvdCveDb.__init__(self, debug)

        if config_file:
            config = CustomParser.CustomParser()
            config.read(config_file)
            self.config = config

        self.config_file = config_file

    def modified_url(self):
        if not os.path.isfile(self.config_file):
            urls = Constants.nvdcve_modified_url
        else:
            urls = self.config.get('Modified')

        return urls

    def recent_url(self):
        if not os.path.isfile(self.config_file):
            urls = Constants.nvdcve_recent_url
        else:
            urls = self.config.get('Recent')
        return urls

    def test_url(self):
        urls = []
        if not os.path.isfile(self.config_file):
            urls.append(Constants.nvdcve_urls[8])
        else:
            urls = self.config.get('Test')
        return urls


    def all_urls(self):
        if not os.path.isfile(self.config_file):
            urls = Constants.nvdcve_urls
        else:
            urls = self.config.get('All')
        return urls

    def initialize(self):
        if os.path.isfile(self.db_name):
            print "Data Base exists!"
            os.remove(self.db_name)

        self.db_init()

    def search(self, argv):
        if argv == None:
            return -1

        data = argv.lower()

        if data.startswith('nvd') or data.startswith('cve'):
            data = data[4:]

        try:
            yr, inc = data.split('-')
        except ValueError:
            return (2)
        except:
            raise

        return self.db_search(data)

    def search_opts(self, opts):
        return self.db_search_opts(opts)

    def do_webify(self,cves):
        for cve in cves:
            webify_cve(cve)

        return True

    def display(self, datum):
        vendors = []
        products = []
        for order in self.order:
            if order == 'Entry':
                for i, array in enumerate(self.entry_db.data_layout):
                    if array[0] == "Vendor":
                        vendors = datum[order][array[0]].split(',')
                        continue

                    if array[0] == "Product":
                        products = datum[order][array[0]].split(',')
                        continue

                    if not array[3]:
                        continue
                    print "%s : %s" % (array[0],datum[order][array[0]])

            if order == 'Sols':
                for i, array in enumerate(self.sols_db.data_layout):
                    if not array[3]:
                        continue
                    print "%s : %s" % (array[0],datum[order][array[0]])
            if order == 'Loss_type':
                for i, array in enumerate(self.loss_type_db.data_layout):
                    if not array[3]:
                        continue
                    print "%s : %s" % (array[0],datum[order][array[0]])
            if order == 'Range':
                for i, array in enumerate(self.range_db.data_layout):
                    if not array[3]:
                        continue
                    print "%s : %s" % (array[0],datum[order][array[0]])

            if order == 'Refs':
                for r in datum['Refs']:
                    for i, array in enumerate(self.refs_db.data_layout):
                        if not array[3]:
                            continue
                        if datum[order][r][array[0]]:
                            print "%s : %s" % \
                                    (array[0],datum[order][r][array[0]])

            if order == 'Desc':
                for i, array in enumerate(self.desc_db.data_layout):
                    if not array[3]:
                        continue
                    print "%s : %s" % (array[0],datum[order][array[0]])

            if order == 'Vers':
                for i in range(0, len(vendors)):
                    versions = []
                    print "\nVendor: %s Product: %s" % (vendors[i], products[i])
                    for v in datum['Vers']:
                        for a, array in enumerate(self.vers_db.data_layout):
                            if not array[3]:
                                continue
                            if datum[order][v]['Product'] == products[i] and datum[order][v]['Vendor'] == vendors[i]:
                                if datum[order][v][array[0]]:
                                    if array[0] == 'Num':
                                        if datum[order][v]['Edition']:
                                            versions.append(datum[order][v][array[0]]+"-"+datum[order][v]['Edition'])
                                        else:
                                            versions.append(datum[order][v][array[0]])

                    versions.sort()
                    for ver in versions:
                        print "Version: %s" % ver

    def cve_display(self, datum):
        '''
            CVE display format
        '''
        print "CVE-ID:"
        print "="*30
        print datum['Entry']['name']
        print "\nDescription"
        print "="*30,
        print datum['Desc']['Desc']
        print "Referneces"
        print "="*30
        s_refs = sorted(datum['Refs'].keys())
        for ref in s_refs:
            print "%s:%s" % \
                    (datum['Refs'][ref]['Source'].strip('n'),datum['Refs'][ref]['Data'].strip('\n'))
            print datum['Refs'][ref]['URL']
            print

        print "Status"
        print "="*30
        print "Phase"
        print "="*30
        print "Votes"
        print "="*30
        print "Comments"
        print "="*30

    def nvd_display(self, datum):
        print "%s" %  datum['Entry']['name']
        print "Summary: %s" % datum['Desc']['Desc'].strip('\n')
        print "Published: %s" % datum['Entry']['published']
        print "CVSS Severity: %s (%s)" % \
                (datum['Entry']['CVSS_score'], datum['Entry']['severity'])

    def download(self, url):
        import urllib
        import gzip

        if not os.path.isdir(Constants.data):
            os.mkdir(Constants.data)

        save_as = os.path.basename(url)
        dest = Constants.data+"/"+save_as
        if os.path.isfile(dest):
            print "File %s exists!" % save_as
            ans = raw_input("Over write [Y,n]? ")
            if ans.lower() in ['n', 'no']:
                return
            print "Removing %s" % dest
            os.remove(dest)

        print "Downloading from %s" % url

        try:
            urllib.urlretrieve(url, filename=dest)
        except urllib2.URLError:
            print "HTTP: connection timed out for %s" % url
            sys.exit(2)
        except (IOError, OSError):
            print "HTTP: check URL %s definition" % url
            raise

        with gzip.open(dest, 'rb') as f:
            file_content = f.read()

        unzip_fname = dest[:-3]
        with open(unzip_fname, 'w') as f:
            f.write(file_content)

        print "Saving as %s to %s" % (dest, unzip_fname)

    def data_import(self, url, local=True):
        if local:
            name = os.path.basename(url)
            src  = Constants.data+"/"+name
            if not os.path.isfile(src):
                print "No local data, downloading"
                self.download(url)
            url = src

        return self.xml_import(url, local)
