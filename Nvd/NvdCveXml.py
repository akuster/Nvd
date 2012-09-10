#
#  Copyright 2010 Armin Kuster <akuster@kama-aina.net>
#
#  This script is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2 as
#  published by the Free Software Foundation.
#
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
import sys
import os
import urllib
import xml.sax
import xml.sax.handler

class NvdCveHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        self.inEntry = 0
        self.inDesc = 0
        self.inRefs = -1
        self.inSol = 0
        self.inLoss_types = 0
        self.inRange = 0
        self.inVers = 0
        self.inVuln_soft = 0
        self.inSec_prot = 0
        self.total = 0

    def startElement(self, name, attributes):
        '''
        entry
         Att -> CVSS_vector, CVSS_base_score, CVSS_exploit_subscore,
         CVSS_impact_subscore, name,  seq, severity, type,
         published CVSS_version, CVSS_score, modified

        desc
            descript
        sols
            sol
                att source
        loss_types
            avail
            conf
            int
            sec_prot
                att other
        range
            network
            local
        refs
            -> ref
                att source & url, patch, adv
        vuln_soft
            -> prod
                att vendor & name
                vers
                    att num
        '''
        if name == 'nvd':
            found_version = attributes['nvd_xml_version']
            supported_version = '1.2'

            if not found_version == supported_version:
                print "Unsupport nvd xml version: %s" % found_version
                exit(1)
            self.mapping = {}

        if name == "entry":
            self.inItem = 1
            self.buffer = ""
            self.entry = {}
            d_entry = {
                    'CVSS_vector': "",
                    'CVSS_base_score': "0",
                    'CVSS_exploit_subscore': "0",
                    'CVSS_impact_subscore': "0",
                    'name': "",
                    'seq': "",
                    'severity': "",
                    'type': "",
                    'published': "" ,
                    'CVSS_version': "0" ,
                    'CVSS_score': "0" ,
                    'modified': "" }

            for e in d_entry.keys():
                try:
                   d_entry[e] = attributes['%s' % e]
                except KeyError:
                    if d_entry[e] != "0":
                        d_entry[e] = ""

            self.cve = d_entry['name']
            self.entry['Entry'] =  d_entry
            self.mapping[self.cve] = self.entry

        if name == 'desc':
            self.inDesc = 1
            self.desc = {}
            d_desc = {
                    'source': '',
                    'desc': ''
                    }

            for e in d_desc.keys():
                try:
                   d_desc[e] = attributes['%s' % e]
                except KeyError:
                    d_desc[e] = ""

            self.desc['Desc'] = d_desc

        if name == 'sols':
            self.inSols = 1
            self.sols = {}

        if name == 'sol':
            self.inSol = 1
            self.sol = {}
            d_sol = {
                    'source': '',
                    'data': ''
                    }

            for e in d_sol.keys():
                try:
                   d_sol[e] = attributes['%s' % e]
                except KeyError:
                    d_sol[e] = ""

            self.sol['Sol'] = d_sol

        if name == 'loss_types':
            self.loss_types = {}
            self.loss_types['Loss_types'] = {}

        if name == 'avail' or name == 'conf' or name == 'int':
            if self.inLoss_types == 0:
                self.loss_types['Loss_types'] = {self.inLoss_types:name}
            else:
                self.loss_types['Loss_types'].update({self.inLoss_types:name})
            self.inLoss_types += 1

        if name == 'sec_prot':
            self.inSec_prot = 1
            self.sec_prot = {}
            self.sec_prot['Sec_prot'] = {}
            d_sec_prot = {
                    'other': '',
                    'admin': '',
                    'user': '',
                    }

            for e in d_sec_prot.keys():
                try:
                   d_sec_prot[e] = attributes['%s' % e]
                except KeyError:
                    d_sec_prot[e] = ""

            self.sec_prot['Sec_prot'] = d_sec_prot

        if name == 'range':
            self.inRange = 0
            self.range = {}

        if name == 'network' or name == 'local' or name == 'user_int':
            if self.inRange == 0:
                self.range['Range'] = {self.inRange:name}
            else:
                self.range['Range'].update({self.inRange:name})
            self.inRange += 1

        if name == 'refs':
            self.refs = {}
            self.refs['Refs'] = {}

        if name == 'ref':
            self.ref = {}
            self.inRefs += 1

            d_ref = {
                'source': "",
                'url': "",
                'patch': "",
                'adv': "",
                'data': "" }

            for r in d_ref.keys():
                try:
                   d_ref[r] = attributes['%s' % r]
                except KeyError:
                   d_ref[r] = ''

            self.ref =  d_ref

        if name == 'vuln_soft':
            self.inVuln_soft = 0
            self.inProd = 0
            self.vuln_soft = {}
            self.vuln_soft['Vuln_soft'] = {}

        if name == 'prod':
            self.vers = {}
            self.inVers = 0

            d_prod = {
                    'vendor': "",
                    'name' : ""
                    }

            for r in d_prod.keys():
                try:
                   d_prod[r] = attributes['%s' % r]
                except KeyError:
                   d_prod[r] = ''

            if self.vuln_soft['Vuln_soft'].has_key(self.inProd):
                self.vuln_soft['Vuln_soft'][self.inProd].update({'Prod': d_prod})
            else:
                self.vuln_soft['Vuln_soft'][self.inProd] = {'Prod': d_prod}

        if name == 'vers':
            d_vers = {
                    'edition': "0",
                    'num': "0"
                    }
            for v in d_vers.keys():
                try:
                   d_vers[v] = attributes['%s' % v]
                except KeyError:
                   d_vers[v] = ''

            if self.inVers == 0:
                self.vers['vers'] = {self.inVers: d_vers}
            else:
                self.vers['vers'].update({self.inVers: d_vers})

            self.inVers += 1


    def characters(self, data):
        import re
        if self.inEntry:
            self.buffer += data

        if self.inDesc:
            self.desc['Desc']['desc'] +=  data.strip(' ')

        if self.inSol:
            self.sol['Sol']['data'] += unicode(re.sub('"', ' ',data.strip(' ')))

        if self.inRefs >= 0:
            self.ref['data'] += data.strip(' ')

        if self.inSec_prot:
            self.sec_prot['Sec_prot'].update({'type': data.strip(' ')})

    def endElement(self, name):
        if name == "entry":
            self.total += 1
            self.inEntry = 0

        if name == 'desc':
            self.inDesc = 0
            self.mapping[self.cve].update(self.desc)

        if name == 'sols':
            self.inSols = 0
            self.mapping[self.cve].update(self.sols)

        if name == 'sol':
            self.inSol = 0
            self.sols['Sols'] = self.sol

        if name == 'loss_types':
            self.inLoss_types = 0
            self.mapping[self.cve].update(self.loss_types)

        if name == 'range':
            self.inRange = 0
            self.mapping[self.cve].update(self.range)

        if name == 'refs':
            self.inRefs = -1
            self.mapping[self.cve].update(self.refs)

        if name == 'ref':
            self.refs['Refs'].update({self.inRefs:self.ref})

        if name == 'vuln_soft':
            self.inVuln_soft = 0
            self.mapping[self.cve].update(self.vuln_soft)

        if name == 'prod':
            self.inVers = 0
            self.inProd += 1

        if name == 'vers':

            if self.vuln_soft['Vuln_soft'].has_key(self.inProd):
                self.vuln_soft['Vuln_soft'][self.inProd].update(self.vers)
            else:
                self.vuln_soft['Vuln_soft'][self.inProd] = self.vers

        if name == 'sec_prot':
            self.inSec_prot = 0
            self.mapping[self.cve].update(self.sec_prot)


class NvdCveXml():

    def __init__(self, debug):
        self.debug = debug
        self.parser = xml.sax.make_parser(  )
        self.handler = NvdCveHandler(  )
        self.parser.setContentHandler(self.handler)

    def xml_import(self, src, local=True):
        self.handler.total = 0
        print "importing ",
        if local:
            print "locally ",
            fd = open(src, 'r')

        if not local:
            print "remote ",
            try:
                fd = urllib.urlopen(src)
            except KeyboardInterrupt:
                pass
                exit(1)
            except:
                raise
        print "file from %s" % src
        try:
            self.parser.parse(fd)
        except KeyboardInterrupt:
            fd.close()
            pass
            exit(1)

        fd.close()
             
        return {self.handler.total: self.handler.mapping}

