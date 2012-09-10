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
import sqlite3
import Constants
from NvdCveDbCommon import DbCommon
from util import inRange

'''

'''

class NvdCveDb_sec_prot(DbCommon):
    '''
        loss_type_id
        type: admin, other
        data
    '''

    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "sec_prot_db"
        self.data_layout = Constants.sec_prot_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, loss_type_id, type):
        cmd = ('SELECT * from %s WHERE loss_type_id=%d and type=%s' %\
                (self.table_name, loss_type_id, type))
        self.cursor.execute
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, loss_id, type, val):
        '''
        '''
        ret = -1
        data = {}
        if val == '' or len(val) == 0:
            return ret

        data.update({'type': type})
        data.update({'loss_type_id': loss_id})
        if self.in_db(loss_id, type):
            ret = 0
        else:
            ret = self.dbc.db_add(data)

        return ret

    def fetchall(self, id):
        return self.dbc.fetch1_by_id('loss_type_id', id)

    def db_table(self):
        return self.dbc.db_table()

class NvdCveDb_range(DbCommon):
    '''
        cve_id
        data (network, local, user_init)
    '''

    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "range_db"
        self.data_layout = Constants.range_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, cve_id, data):
        cmd = ('SELECT * from %s WHERE cve_id=%d and data=%s' %\
                (self.table_name, cve_id, data))
        self.cursor.execute
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, cve_id, datum):
        '''
        '''
        data = {}
        if datum== {}:
            return ret

        data.update({'cve_id': cve_id})
        data.update({'data': datum})
        ret = -1
        if self.in_db(cve_id, data['data']):
            ret = 0
        else:
            ret = self.dbc.db_add(data)
        return ret

    def fetchall(self, id):
        return self.dbc.fetch1_by_id('cve_id', id)

    def db_table(self):
        return self.dbc.db_table()

class NvdCveDb_loss_type(DbCommon):
    '''
        cve id
        type (avail, conf, int, sec_prot)
        data
    '''

    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "loss_type_db"
        self.data_layout = Constants.loss_types_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, cve_id, data):
        cmd = ('SELECT * from %s WHERE cve_id=%d and type=%s' %\
                (self.table_name, cve_id, data))
        self.cursor.execute
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, cve_id, info):
        '''
        '''
        data = {}
        data.update({'cve_id': cve_id})
        data.update({'data': info})

        ret = -1
        if self.in_db(cve_id, data['data']):
            ret = 0
        else:
            ret = self.dbc.db_add(data)

        return ret

    def fetchId(self, id):
        return self.dbc.fetch1_by_id('cve_id', id)

    def fetchall(self, id):
        return self.dbc.fetch1_by_id('cve_id', id)

    def db_table(self):
        return self.dbc.db_table()

class NvdCveDb_refs(DbCommon):
    '''
        cve id
        source
        url
        data
    '''

    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "refs_db"
        self.data_layout = Constants.ref_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, cve_id, data):
        cmd = ('SELECT * from %s WHERE cve_id=%d and data=%s' %\
                (self.table_name, cve_id, data['data']))
        self.cursor.execute
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, cve_id, data):
        '''
            Need cve id number
            data
        '''
        info = {}
        ret = -1
        info = data
        info.update({"cve_id": cve_id})

        if self.in_db(cve_id, data):
            ret = 0
        else:
            ret = self.dbc.db_add(info)

        return ret

    def fetchall(self, id):
        return self.dbc.fetchall_by_id('cve_id', id)

    def db_table(self):
        return self.dbc.db_table()


class NvdCveDb_entry(DbCommon):
    def __init__(self, db):
        self.table_name = "cve_db"
        self.db = db
        self.cursor = self.db.cursor()
        self.data_layout = Constants.cve_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, data):
        cmd = ('SELECT * from %s WHERE seq="%s"' % \
                (self.table_name, data['seq']))
        self.cursor.execute(cmd)
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, entry, sol_id, desc_id, vendors, products):
        '''
        '''
        ret = -1
        data = {}
        if entry == {}:
            return ret

        data = entry
        data.update({'desc_id': desc_id})
        data.update({'sol_id': sol_id})
        data.update({'vendor': vendors})
        data.update({'prod': products})

        if self.in_db(data):
            ret = 0
        else:
            ret = self.dbc.db_add(data)

        return ret

    def fetchIds(self, seq):
        cve_id = None
        sol_id = None
        desc_id = None

        if self.in_db({'seq':seq}):
            cmd = ('SELECT * from %s WHERE seq="%s"' % \
                (self.table_name, seq))
            self.cursor.execute(cmd)
            db_search = self.cursor.fetchone()

            cve_id = db_search[0]
            desc_id = db_search[13]
            sol_id = db_search[14]

        return (cve_id, sol_id, desc_id)

    def fetchall(self, seq):
        return self.dbc.fetch1_by_id('seq', seq)

    def db_table(self):
        return self.dbc.db_table()

    def find(self, vendor, prod, id=None):
        cve_list = []
        tags = ['name']

        tags.append("vendor")
        if prod:
            tags.append("prod")


        cves = self.dbc.fetchall_by_tags(tags)

        for cve in cves:
            if vendor not in cve[1]:
                continue

        
            if  prod != None and prod not in cve[2]:
                continue

            if cve[0] not in cve_list:
                #print "%s %s %s" % (cve[0], cve[1], cve[2])
                cve_list.append(cve[0])

        cve_list.sort()
        return cve_list


    def fetch_cve_by_id(self, id):
        cve_table = self.dbc.fetch1_by_id('id', id)
        return cve_table

    def fetch_cve_by_prod_id_by_range(self, id, start, end):
        cve_table = self.dbc.fetch1_by_id('prod_id', id)
        return cve_table

class NvdCveDb_desc(DbCommon):
    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "desc_db"
        self.data_layout = Constants.desc_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, data):
        cmd = ('SELECT * from %s WHERE source=%s and desc=%s' %\
                (self.table_name, data['source'],data['desc']))
        self.cursor.execute
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, data):
        '''
            requires cve_id, source and data
        '''
        ret = -1
        if data == {}:
            return ret

        if self.in_db(data):
            ret = 0
        else:
            ret = self.dbc.db_add(data)

        return ret

    def fetchall(self, id):
        return self.dbc.fetch1_by_id('id', id)

    def db_table(self):
        return self.dbc.db_table()

class NvdCveDb_sol(DbCommon):
    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "sol_db"
        self.data_layout = Constants.sol_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, data):
        cmd = ('SELECT * from %s WHERE sol=%s and source=%s' %\
                (self.table_name, data['source'],data['data']))
        self.cursor.execute
        found = self.cursor.fetchone()
        if found == None:
            return 0
        else:
            return 1

    def add(self, data):
        '''
            requires vendor name  and product name
            we look up vendor_id from the vendor name
        '''
        ret = -1
        if data == {}:
            return ret

        if self.in_db(data):
            ret = 0
        else:
            ret = self.dbc.db_add(data)

        return ret

    def fetchall(self, id):
        return self.dbc.fetch1_by_id('id', id)

    def db_table(self):
        return self.dbc.db_table()

class NvdCveDb_ver(DbCommon):
    def __init__(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = "ver_db"
        self.data_layout = Constants.ver_db
        self.dbc = DbCommon(db, self.table_name, self.data_layout)

    def db_init(self, db):
        self.db = db
        self.cursor = self.db.cursor()
        self.dbc = DbCommon(db, self.table_name, self.data_layout)
        self.dbc.db_init()

    def in_db(self, cve, vendor, product, num):
        cmd = ('SELECT * from %s WHERE cve_id=%d and vendor=%s and product=%s and num=%s' %\
                (self.table_name, cve, vendor, product, num))
        self.cursor.execute
        found = self.cursor.fetchone()

        if found:
            return 1

        return 0

    def add(self, cve, vendor, product, indata):
        '''
            requires vendor name  and product name
            we look up vendor_id from the vendor name
        '''
        data = {}
        data.update({'cve_id': cve})
        data.update({'vendor': vendor})
        data.update({'prod': product})
        data.update(indata)

        ret = -1
        if self.in_db(cve, vendor, product, indata['num']):
            ret = 0
        else:
            ret = self.dbc.db_add(data)

        return ret

    def fetchall(self, id):
        return self.fetchall_by_id('cve_id', id)

    def db_table(self):
        return self.dbc.db_table()


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
        self.db_name = Constants.working_dir+"/"+ Constants.DBname
        self.db = None
        if not self.__connect():
            return

        self.vers_db = NvdCveDb_ver(self.db)
        self.sols_db = NvdCveDb_sol(self.db)
        self.entry_db = NvdCveDb_entry(self.db)
        self.refs_db = NvdCveDb_refs(self.db)
        self.range_db = NvdCveDb_range(self.db)
        self.loss_type_db = NvdCveDb_loss_type(self.db)
        self.sec_prot_db = NvdCveDb_sec_prot(self.db)
        self.desc_db = NvdCveDb_desc(self.db)

    def __connect(self):
        if self.db == None:
            if not os.path.isdir(Constants.working_dir):
                print "Making working dir"
                os.mkdir(Constants.working_dir)
            try:
                self.db = sqlite3.connect(self.db_name)
            except sqlite3.OperationalError:
                print "Database not initialized!"
                return 0

        return 1

    def db_init(self):
        self.db = None
        if os.path.isfile(self.db_name):
            os.remove(self.db_name)

        if self.__connect():
            self.vers_db.db_init(self.db)
            self.sols_db.db_init(self.db)
            self.entry_db.db_init(self.db)
            self.desc_db.db_init(self.db)
            self.refs_db.db_init(self.db)
            self.range_db.db_init(self.db)
            self.loss_type_db.db_init(self.db)
            self.sec_prot_db.db_init(self.db)

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
            if self.entry_db.in_db(entry_data):
                count += 1
                self.__progress(count, total)
                continue

            try:
                s_data = data[cve]['Sols']['Sol']
                sols_id = self.sols_db.add(s_data)
            except KeyError:
                pass

            try:
                desc_data = data[cve]['Desc']
                desc_id = self.desc_db.add(desc_data)
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

            entry_id = self.entry_db.add(entry_data, sols_id, desc_id, vendors, products)
            if entry_id == None:
                raise

            try:
                vuln_soft = data[cve]['Vuln_soft']

                for v in vuln_soft:
                    vendor = vuln_soft[v]['Prod']['vendor']
                    product = vuln_soft[v]['Prod']['name']
                    for ver in vuln_soft[v]['vers']:
                        self.vers_db.add(entry_id, vendor, product, vuln_soft[v]['vers'][ver])

            except KeyError:
                pass

            try:
                refs = data[cve]['Refs']
                for ref in refs:
                    refs_id = self.refs_db.add(entry_id, refs[ref])
            except KeyError:
                pass

            try:
                ranges = data[cve]['Range']
                for r in ranges:
                    range_id = self.range_db.add(entry_id, ranges[r])
            except KeyError:
                pass

            try:
                losses = data[cve]['Loss_types']
                for l in losses:
                    loss_id = self.loss_type_db.add(entry_id, losses[l])
            except KeyError:
                pass

            try:
                sec_prots = data[cve]['Sec_prot']
                for s in sec_prots:
                    sec_id = self.sec_prot_db.add(loss_id, s, sec_prots[s])
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
