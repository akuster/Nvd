import os
import sys
from sqlalchemy import *
from sqlalchemy import orm
from sqlalchemy.exc import OperationalError

import sqlalchemy as sa

import config as settings

__all__ = ['Engine']

class _data(object):
    def __init__(self,values):
        self.__dict__.update(values)

    def __getitem__(self, index):
        return self.__dict__[index]

    def __iter__(self):
        return iter(self.__dict__)

class _base(object):
    def __init__(self):
        __databases = settings.DATABASES
        for name, db_data in __databases.items():
            a = _data(db_data)
            self.__dict__.update({name: a})
            
    def __iter__(self):
        return iter(self.__dict__)

    def __getitem__(self, index):
        return self.__dict__[index]

    def engine(self, index):
        try:
            return self.__dict__[index]['ENGINE']+":////"+self.__dict__[index]['NAME']
        except KeyError:
            print "Invalid engine name"
            sys.exit(1)
        except:
            raise

class Engine():
    engine = None
    session = None
    def __init__(self):
        if self.connection == None:
            raise

        try:
            e = _base()
        except:
            raise

        try:
            config = e.engine(self.connection)
        except:
            raise
        try:
            engine = sa.create_engine(config)
        except:
            raise

        try:
            #sm = orm.sessionmaker(autoflush=True, bind=engine)
            sm = orm.sessionmaker(bind=engine)
        except:
            raise

        try:
            self.Session = orm.scoped_session(sm)
        except:
            raise

        self.engine = engine

