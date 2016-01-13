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
from Db import *
from util import inRange

'''

'''
class NvdCveDb():
    '''
        Database class for nvd cve data.
        cve_db
            entry:
            - CVSS_vector
            - CVSS_base_score
            - CVSS_exploit_subscore
            - CVSS_impact_subscore
            - name
            - seq
            - severity
            - type
            - published
            - CVSS_version
            - CVSS_score
            - modified
            desc:
            - descript
            range: (network, local)
            sol id
            loss_type id
            vendors
            products

        sol_db:
            - cve id
            - sol
            - source
        loss_types:
            - cve id
            - type (avail, conf, int, sec_prot)
            - data

        ref_db:
            - cve id
            - source
            - url
            - data

        ver_db
            - cve id
            - vendor
            - product
            - num
    '''
    def __init__(self, debug=0):
        self.debug = debug
        self.verbose = 0
        self.order = []

        self.vers_db = Ver()
        self.sols_db = Sol()
        self.entry_db = Cve()
        self.refs_db = Ref()
        self.range_db = Range()
        self.loss_type_db = LossType()
        self.sec_prot_db = SecProt()
        self.desc_db = Desc()


    def __progress(self, count, total ):
            percent = ((1.0*count/total)*100)
            sys.stdout.write("\rCVE processed:  %2.1f%% (%d/%d)" % (percent, count, total))
            sys.stdout.flush()

    def db_add(self,mapping):
        count = 0
        total = mapping.keys()[0]
        data = mapping[total]

        for cve in data:
            prod_id = -1
            sols_id = -1
            vendors = ""
            products = ""
        
            try:
                entry_data = data[cve]['Entry']
            except KeyError:
               raise

            # check to see if cve is in db
            if self.entry_db.in_db(**entry_data):
                count += 1
                self.__progress(count, total)
                continue

            try:
                s_data = data[cve]['Sols']['Sol']
                sols_id = self.sols_db.add(**s_data)
            except KeyError:
                pass

            try:
                desc_data = data[cve]['Desc']
                desc_id = self.desc_db.add(**desc_data)
            except KeyError:
                pass

            try:
                vuln_soft = None
                vuln_soft = data[cve]['Vuln_soft']
            except KeyError:
                pass

            if vuln_soft:
                for v in vuln_soft:
                    if vuln_soft[v]['Prod']['vendor'] not in vendors:
                        vendors += vuln_soft[v]['Prod']['vendor']+","
                    if vuln_soft[v]['Prod']['name'] not in products:
                        products += vuln_soft[v]['Prod']['name']+","
                vendors = vendors[:-1]
                products = products[:-1]

            entry_data.update({'desc_id': desc_id})
            entry_data.update({'sol_id': sols_id})
            entry_data.update({'vendor': vendors})
            entry_data.update({'prod': products})

            entry_id = self.entry_db.add(**entry_data)
            if entry_id == None:
                raise

            try:
                vuln_soft = data[cve]['Vuln_soft']

                for v in vuln_soft:
                    vendor = vuln_soft[v]['Prod']['vendor']
                    product = vuln_soft[v]['Prod']['name']
                    for ver in vuln_soft[v]['vers']:
                        self.vers_db.add(cve_id='%s' %entry_id, vendor='%s' %vendor, product='%s' %product, num='%s' %vuln_soft[v]['vers'][ver])

            except KeyError:
                pass

            try:
                refs = data[cve]['Refs']
                for ref in refs:
                    refs_id = self.refs_db.add(cve_id="%s" % entry_id, data="%s" % refs[ref])
            except KeyError:
                pass

            try:
                ranges = data[cve]['Range']
                for r in ranges:
                    range_id = self.range_db.add(cve_id='%s' % entry_id, data='%s' % ranges[r])
            except KeyError:
                pass

            try:
                losses = data[cve]['Loss_types']
                for l in losses:
                    loss_id = self.loss_type_db.add(cve_id='%s' % entry_id, type='%s' % losses[l])
            except KeyError:
                pass

            try:
                sec_prots = data[cve]['Sec_prot']
                for s in sec_prots:
                    sec_id = self.sec_prot_db.add(loss_type_id='%s' % loss_id, data='%s' % sec_prots[s])
            except KeyError:
                pass
            count += 1
            self.__progress(count, total)
        print 

    def db_search(self, cve_number):
        table = {}
        cve_id, sol_id, desc_id  = self.entry_db.fetchIds(cve_number)
        d_entry = self.entry_db.fetchall(cve_number)
        table['Entry'] = d_entry
        self.order.append('Entry')

        d_desc = self.desc_db.fetchall(desc_id)
        if d_desc != None:
            table['Desc'] = d_desc
            self.order.append('Desc')

        d_sols = self.sols_db.fetchall(sol_id)
        if d_sols != None:
            table['Sols'] = d_sols
            self.order.append('Sols')

        loss_id = self.loss_type_db.fetchId(cve_id)
        if loss_id != None:
            d_loss_types = self.loss_type_db.fetchall(cve_id)
            table['Loss_type'] = d_loss_types
            self.order.append('Loss_type')
            d_sec_prot = self.sec_prot_db.fetchall(loss_id)
            if d_sec_prot != None:
                table['Sec_prot'] = d_sec_prot
                self.order.append('Sec_proc')

        d_range = self.range_db.fetchall(cve_id)
        if d_range != None:
            table['Range'] = d_range
            self.order.append('Range')

        d_refs = self.refs_db.fetchall(cve_id)
        if d_refs != None:
            table['Refs'] = d_refs
            self.order.append('Refs')

        d_vers = self.vers_db.fetchall(cve_id)

        if d_vers != None:
            table['Vers'] = d_vers
            self.order.append('Vers')

        if table == None:
            return 0
        else:
            return table


    def db_search_opts(self, opts):
        cves = 0
        vendor = product = ""
        version_start = version_stop = None
        skipped = 0
        total = 0
        good = 0
        year = 0

        for opt in opts:
            key, value = opt.split("=")

            if 'vendor' == key.lower():
                vendor =value 

            if 'prod' == key.lower():
                product = value

            if 'start' == key.lower():
                version_start = value

            if 'stop' == key.lower():
                version_stop = value

            if 'yr' == key.lower():
                year = int(value)

        if vendor or (vendor and product):
            cves = self.entry_db.find(vendor, product)

        if cves:
            cve_table = []
            for cve in cves:
                if self.verbose:
                    print "Processing: %s" % cve

                total += 1

                if year and year != int(cve.split('-')[1]):
                    skipped += 1
                    continue

                cve_id, sol_id, desc_id  = self.entry_db.fetchIds(cve[4:])

                d_vers = self.vers_db.fetchall(cve_id)
                for version in d_vers:
                    if self.verbose:
                        print "Checking version : %s (%s %s)" % (d_vers[version]['Num'], version_start, version_stop)

                    ret = inRange(d_vers[version]['Num'], version_start, version_stop)
                    if self.verbose:
                        print ret

                    if ret == -3:
                        print "Error in inRange: %s" % cve_id
                        sys.exit(1)
                        return(good, skipped, total, [])

                    if ret == True:
                        if cve not in cve_table:
                            cve_table.append(cve)
                            good += 1

        return (good, skipped, total, cve_table)


#def test(cve):
    #x = Cve()
#
#if __name__ == "__main__":
    #import sys
    #sys.exit(test(sys.argv[1]))
