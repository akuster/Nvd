from sqlalchemy import Column, Integer, String, Date, Sequence
from sqlalchemy.ext.declarative import declarative_base
from engine import Engine
import Constants

Base = declarative_base()

class DbErrorLow(Exception):
    pass

class Version_Db(Base):
    __tablename__ = 'ver_db'
    id = Column('id', Integer, primary_key=True)
    cve_id = Column('cve_id', Integer ) 
    vendor  = Column('vendor', String(30))
    product  = Column('prod', String(30))
    edition  = Column('edition', String(30))
    num  = Column('num', String(10))

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', cve_id='%s', vendor='%s', product='%s', edition='%s', num='%s' " %  \
        (self.id, self.cve_id, self.vendor, self.product, self.edition, self.num)

class Desc_Db(Base):
    __tablename__ = 'desc_db'
    id = Column('id', Integer, primary_key=True)
    source = Column('source', String)
    desc = Column('desc', String)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', source='%s', desc='%s'" %  \
        (self.id, self.source, self.desc)

class Sol_Db(Base):
    __tablename__ = 'sol_db'
    id = Column('id', Integer, primary_key=True)
    source = Column('source', String)
    data = Column('data', String)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', source='%s', data='%s'" %  \
        (self.id, self.source, self.data)

class Cve_Db(Base):
    __tablename__ = 'cve_db'
    id = Column('id', Integer, primary_key=True)
    seq = Column('seq', String(10))
    CVSS_vector = Column('CVSS_vector', String)
    CVSS_base_score = Column('CVSS_base_score', String(5))
    CVSS_exploit_subscore = Column('CVSS_exploit_subscore', String(5))
    CVSS_impact_subscore = Column('CVSS_impact_subscore', String(5))
    name = Column('name', String(14))
    severity = Column('severity', String(7))
    type = Column('type', String(4))
    published = Column('published', String(10))
    CVSS_version = Column('CVSS_version', String(5))
    CVSS_score = Column('CVSS_score', String(5))
    modified = Column('modified', String(10))
    desc_id = Column('desc_id', Integer)
    sol_id = Column('sol_id', Integer)
    vendor = Column('vendor', String)
    prod = Column('prod', String)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id = '%s', seq = '%s', CVSS_vector = '%s', CVSS_base_score = '%s', CVSS_exploit_subscore = '%s', CVSS_impact_subscore = '%s', name = '%s', severity = '%s', type = '%s', published = '%s', CVSS_version = '%s', CVSS_score = '%s', modified = '%s', desc_id = '%s', sol_id = '%s', vendor = '%s', prod = '%s'" %  (self.id, self.seq, self.CVSS_vector, self.CVSS_base_score,self.CVSS_exploit_subscore, self.CVSS_impact_subscore, self.name, self.severity, self.type, self.published, self.CVSS_version, self.CVSS_score, self.modified, self.desc_id, self.sol_id, self.vendor, self.prod) 


class Ref_Db(Base):
    __tablename__ = 'refs_db'
    id = Column('id', Integer, primary_key=True)
    cve_id = Column('cve_id', Integer ) 
    source = Column('source', String)
    patch = Column('patch', String(2))
    url = Column('url', String)
    adv = Column('adv', String(2))
    data = Column('data', String)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', cve_id='%s', source='%s', patch='%s', url='%s', adv='%s', data='%s'" %  \
        (self.id, self.cve_id, self.source, self.patch, self.url, self.adv, self.data)

class Range_Db(Base):
    __tablename__ = 'range_db'
    id = Column('id', Integer, primary_key=True)
    cve_id = Column('cve_id', Integer ) 
    data = Column('data', String(10))

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', cve_id='%s', data='%s'" %  \
        (self.id, self.cve_id, self.data)

class Loss_types_Db(Base):
    __tablename__ = 'loss_type_db'
    id = Column('id', Integer, primary_key=True)
    cve_id = Column('cve_id', Integer ) 
    type = Column('type', String(6))

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', cve_id='%s', type='%s'" %  \
        (self.id, self.cve_id, self.type)

    def fetchId(self, cve_id) :
        return self.Session.query(self.DB_TABLE).filter_by(cve_id='%s' % cve_id).first()

class Sec_prot_Db(Base):
    __tablename__ = 'sec_prot_db'
    id = Column('id', Integer, primary_key=True)
    loss_type_id = Column('loss_type_id', Integer ) 
    type = Column('type', String(6))
    data = Column('data', String)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return "id='%s', cve_id='%s', type='%s', data='%s'" %  \
        (self.id, self.cve_id, self.type, self.data)


########################
# main database classes
########################

class _DB(Engine):
    connection = 'nvdcvedb'

    def __init__(self):
        Engine.__init__(self)
        Base.metadata.create_all(self.engine, checkfirst=True)

    def add(self, **kwargs):
        id = -1
        try:
            id = self.Session.query(self.DB_TABLE).filter_by(**kwargs).first()
        except AttributeError:
            pass

        if id == None:
            try:
                add_obj = self.DB_TABLE(**kwargs)
                self.Session.add(add_obj)
                self.Session.commit()
                id = add_obj.id
            except:
                raise DBErrorLow
        return id

    def update(self, **kwargs):
        id = -1
        try:
            update_obj = self.DB_TABLE(**kwargs)
            id = self.Session.query(self.DB_TABLE).filter_by(**kwargs).id
            update_obj.id = id
            self.Session.merge(update_obj, load=True)
            self.Session.commit() 
        except:
            raise

        return id

    def delete(self, **kwargs):
        id = -1
        try:
            del_obj = self.Session.query(self.DB_TABLE).filter_by(**kwargs).first()
            self.Session.delete(del_obj)
            self.Session.commit() 
            id = 0
        except AttributeError:
            pass

        return id

    def in_db(self, filter, **kwargs):
        found = self.Session.query(self.DB_TABLE).filter_by(**kwargs).first()
        if found == None:
            return 0
        else:
            return 1

    def fetchall(self, id) :
        return self.Session.query(self.DB_TABLE).filter_by(id='%s' % id).first()

    def fetchId(self, cve_id) :
        return self.Session.query(self.DB_TABLE).filter_by(cve_id='%s' % cve_id).first()

    def filter(self, **kwargs):
        return self.Session.query(self.DB_TABLE).filter_by(**kwargs).first()

    def filter_exact(self, **kwargs):
        ret = self.Session.query(slef.DB_TABLE).filter_by(**kwargs).all()
        if ret:
            return ret
        else:
            raise DbErrorLow

class Ver(Version_Db,_DB):
    DB_TABLE = Version_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.ver_db 

    def fetchall(self, id) :
        return  self.Session.query(self.DB_TABLE).filter_by(id='%s' % id).all()

    def filter_contains(self, **kwargs):
        name = kwargs.get('name')
        ret =  self.Session.query(Version_Db).from_statement("SELECT * FROM package_db WHERE name LIKE '%s%%' " % name).all()
        if ret:
            return ret
        else:
            raise

class Desc(Desc_Db, _DB):
    DB_TABLE = Desc_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.desc_db

class Sol(Sol_Db, _DB):
    DB_TABLE = Sol_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.sol_db 

class Ref(Ref_Db, _DB):
    DB_TABLE = Ref_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.ref_db 

    def add(self, **kwargs):
        id = -1
        if kwargs == {}:
            return id 

        try:
            id = self.Session.query(self.DB_TABLE).filter_by(**kwargs).first()
        except AttributeError:
            pass

        if id == None:
            try:
                add_obj = self.DB_TABLE(**kwargs)
                self.Session.add(add_obj)
                self.Session.commit()
                id = add_obj.id
            except:
                raise
        #    except:
        #        raise DBErrorLow
        return id

        
    def fetchall(self, cve_id) :
        return  self.Session.query(self.DB_TABLE).filter_by(cve_id='%s' % cve_id).all()


class Range(Range_Db, _DB):
    DB_TABLE = Range_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.range_db 

class SecProt(Sec_prot_Db, _DB):
    DB_TABLE = Sec_prot_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.sec_prot_db

class LossType(Loss_types_Db, _DB):
    DB_TABLE = Loss_types_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.loss_types_db

    def fetchId(self, id) :
        return  self.Session.query(self.DB_TABLE).filter_by(cve_id='%s' % id).first().id

class Cve(Cve_Db, _DB):
    DB_TABLE = Cve_Db

    def __init__(self):
        _DB.__init__(self)
        self.data_layout = Constants.cve_db

    def in_db(self, **kwargs):
        id = -1
        try:
            id = self.Session.query(self.DB_TABLE).filter_by(seq='%s' % kwargs.git('seq')).first()
        except AttributeError:
            pass

        if id == None or id == -1:
            return 0
        else:
            return 1


    def add(self, **kwargs):
        id = -1
        if kwargs == {}:
            return id 

        try:
            id = self.Session.query(self.DB_TABLE).filter_by(seq='%s' % kwargs.get('seq')).first()
        except AttributeError:
            pass

        if id == None:
            try:
                add_obj = self.DB_TABLE(**kwargs)
                self.Session.add(add_obj)
                self.Session.commit()
                id = add_obj.id
            except:
                raise
        #    except:
        #        raise DBErrorLow
        return id

    def fetchall(self, seq) :
        return self.Session.query(self.DB_TABLE).filter_by(seq='%s' % seq).all()

    def fetchIds(self, seq):
        db_search = self.Session.query(self.DB_TABLE).filter_by(seq='%s' % seq).first()
        if db_search != None:
            cve_id = db_search.id
            sol_id = db_search.sol_id
            desc_id = db_search.desc_id
        else:
            cve_id = None
            sol_id = None
            desc_id = None

        return (cve_id, sol_id, desc_id)
