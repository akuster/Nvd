#
#  Copyright 2010-2011 Armin Kuster <akuster@kama-aina.net>
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

'''

'''

class DbCommon():
    '''
    '''

    def __init__(self, db, tablename, db_table):
        self.debug = 0
        self.db_initialized = 0
        self.db = db
        self.cursor = self.db.cursor()
        self.table_name = tablename
        self.data_layout = db_table

    def db_init(self):
        if self.db_initialized:
            return 0

        cursor = self.cursor
        cmd = ('CREATE TABLE %s ' % self.table_name)

        TABLE = "(id INTEGER PRIMARY KEY"
        for text, db_name, data_type, display in self.data_layout:
            if db_name != None:
                TABLE = ("%s, %s %s" % (TABLE, db_name, data_type))

        TABLE = TABLE+" )"

        try:
            cursor.execute('%s %s' % (cmd, TABLE))
        except sqlite3.OperationalError:
            raise
            #pass
        else:
            self.db.commit()

            self.db_initialized = 1

        return 1

    def db_add(self, data):

        ret = 0
        if data == {} or data == None or data == "":
            print "Error: missing data."
            return None
        indata = []
        for text, db_name, data_type, display in self.data_layout:
            if db_name in data:
                indata.append(data[db_name])
            else:
                indata.append("")
        # armin
        format = "NULL"
        for i in range(0,len(indata)):
            format +=",?"

        try:
            self.cursor.execute("INSERT INTO "+self.table_name+" VALUES ("+format+")", indata)
        except:
            raise
        else:
            self.db.commit()
            ret = self.cursor.lastrowid

        return ret

    def db_update(self, id, data):

        if data == {}:
            return 0

        cmd = ('UPDATE %s SET' % self.table_name)

        anding = 0
        for text, name, data_type, display in self.data_layout:
            if name in data:
                if name == None:
                    continue
                if not anding:
                    cmd = ("%s %s='%s'" % (cmd, name, data[name]))
                    anding = 1
                else:
                    cmd = ("%s, %s='%s'" % \
                    (cmd, name, data[name]))

        table = " WHERE id=%d" % int(id)

        #if self.debug:
            #print "</br>update: %s %s</br>" % (cmd, table)

        try:
            self.cursor.execute('%s %s' % (cmd, table))
        except:
            raise
        else:
            self.db.commit()

        return 1

    def db_delete(self, id):
        '''
            Inputs:
        '''
        if id == None:
            return 0

        cmd = 'DELETE from %s WHERE id="%s"' % \
        (self.table_name, str(id))
        #if self.debug:
            #print "DELETE: %s" % (cmd)

        try:
            self.cursor.execute('%s' % cmd)
        except:
            raise
        else:
            self.db.commit()

        return 1

    def in_db(self, data):
        if data == {}:
            return -1 

        cmd = ('SELECT * from %s WHERE' % self.table_name)
        anding = 0
        for text, db_name, data_type, display in self.data_layout:
            if db_name in data:
                if db_name == None:
                    continue
                if not anding:
                    cmd += (" %s='%s'" % (db_name, data[db_name]))
                    anding = 1
                else:
                    cmd += (" and %s='%s'" % \
                    (db_name, data[db_name]))

        if self.debug:
            print "in db: %s" % cmd

        try:
            self.cursor.execute(cmd)
        except:
            raise

        found  = self.cursor.fetchall()
        if found == []:
            return 0
        else:
            return 1

    def db_table(self):
        return self.data_layout

    def fetch_raw_by_id(self, tag, id):
        cmd = ('SELECT * from %s WHERE %s="%s"' % \
                (self.table_name, tag, id))
        self.cursor.execute(cmd)
        db_return = self.cursor.fetchall()
        return db_return

    def fetchall_by_tags(self, tags):
        cmd = 'SELECT '
        for tag in tags:
            cmd += tag
            cmd += ","
        cmd = cmd[:-1]
        cmd += ' from '
        cmd += self.table_name

        self.cursor.execute(cmd)
        db_return = self.cursor.fetchall()
        return db_return

    def fetch1_by_id(self, tag, id):
        table = {}
        cmd = ('SELECT * from %s WHERE %s="%s"' % \
                (self.table_name, tag, id))
        self.cursor.execute(cmd)
        db_return = self.cursor.fetchone()
        if db_return == None:
            return

        for i, array in enumerate(self.data_layout):
            table.update({array[1]: db_return[i+1]})
        return table

    def fetchall_by_id(self, tag, id):
        table = {}
        cmd = ('SELECT * from %s WHERE %s="%s"' % \
                (self.table_name, tag, id))
        self.cursor.execute(cmd)
        db_return = self.cursor.fetchall()
        if db_return == None:
            return table

        for d in db_return:
            for i, array in enumerate(self.data_layout):
                if i == 0:
                    table[d[0]] = {array[1]: d[i+1]}
                else:
                    table[d[0]].update({array[1]: d[i+1]})

        return table

    def fetch_id(self, tag, id):
        cmd = ('SELECT id from %s WHERE %s="%s"' % \
                (self.table_name, tag, id))
        self.cursor.execute(cmd)
        db_return = self.cursor.fetchone()
        if db_return == None:
            return

        return db_return[0]

    def fetchall_ids(self, tag, id):
        cmd = ('SELECT id from %s WHERE %s="%s"' % \
                (self.table_name, tag, id))
        self.cursor.execute(cmd)
        db_return = self.cursor.fetchall()
        if db_return == None:
            return

        return db_return


    def fetch_id_by_tags(self, data):
        if data == {}:
            return -1 

        cmd = ('SELECT id from %s WHERE' % self.table_name)
        where = ""
        anding = 0

        for text, db_name, data_type, display in self.data_layout:
            if db_name in data:
                if db_name == None:
                    continue
                if not anding:
                    where = (" %s='%s'" % (db_name, data[db_name]))
                    anding = 1
                else:
                    where += (" and %s='%s'" % \
                    (db_name, data[db_name]))

        if where:
            cmd += where
            self.cursor.execute(cmd)
            db_return = self.cursor.fetchone()
            if db_return == None:
                return None
            return db_return[0]
        else:
            return None

    def fetchone_complex(self, columns=[], where={}, all=None):

        if columns == [] and where == {}:
            return None

        cmd = ('SELECT ')
        if columns == None:
            cmd += "*"
        else:
            anding = 0
            col = ""
            for text, db_name, data_type, display in self.data_layout:
                for column in columns:
                    if column == db_name:
                        col += column
                        col += ","
                        break

            if col == "":
                return -1

            cmd += col[:-1]

        cmd += (' from %s WHERE' % self.table_name)
        
        anding = 0
        for text, db_name, data_type, display in self.data_layout:
            for k, v in where.iteritems():
                if k == db_name:
                    if not anding:
                        cmd += (" %s='%s'" % (k, v))
                        anding = 1
                    else:
                        cmd += (" and %s='%s'" % (k, v))
                    break
        self.cursor.execute(cmd)
        if all:
            db_return = self.cursor.fetchall()
        else:
            db_return = self.cursor.fetchone()

        if db_return == None:
            return None
        return db_return

    def fetch_date_range(self, columns=None, where=None, begin=None, end=None):
        if where == None or begin == None or end == None:
            return None

        cmd = """SELECT """

        if columns == None:
            cmd += "*"
        else:
            anding = 0
            col = ""
            for text, db_name, data_type, display in self.data_layout:
                for column in columns:
                    if column == db_name:
                        col += column
                        col += ","
                        break

            if col == "":
                return -1

            cmd += col[:-1]

        cmd += """ from %(table)s WHERE %(where)s """ % {'table': self.table_name, 'where':  where}
        cmd += """ between '%(begin)s' and '%(end)s' """ % {'begin': begin, 'end': end}
        try:
            self.cursor.execute(cmd)
        except:
            raise
        return self.cursor.fetchall()

    def fetch_where_and_date_range(self, columns=[], where={}, date_column=None, begin=None, end=None):

        if columns == [] and where == {} or date_column == None or begin == None or end == None:
            return None

        cmd = ('SELECT ')
        if columns == None:
            cmd += "*"
        else:
            anding = 0
            col = ""
            for text, db_name, data_type, display in self.data_layout:
                for column in columns:
                    if column == db_name:
                        col += column
                        col += ","
                        break

            if col == "":
                return -1

            cmd += col[:-1]

        cmd += """ from %(table)s WHERE """ % {'table': self.table_name}
        
        anding = 0
        for text, db_name, data_type, display in self.data_layout:
            for k, v in where.iteritems():
                if k == db_name:
                    if not anding:
                        cmd += (" %s='%s'" % (k, v))
                        anding = 1
                    else:
                        cmd += (" and %s='%s'" % (k, v))
                    break

        cmd += """ and %(date_col)s between '%(begin)s' and '%(end)s' """ % {'date_col': date_column, 'begin': begin, 'end': end}

        self.cursor.execute(cmd)
        return self.cursor.fetchall()

