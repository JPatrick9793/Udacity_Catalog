#! --shebang
# DB FILE FOR CATALOG PROJECT
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship # sessionmaker
from sqlalchemy import create_engine
import random, string 

'''
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
'''

Base = declarative_base()

secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)

    @property
    def serialize(self):
        return {
        'id'           : self.id,
        'username'     : self.username,
        'email'        : self.email,
            }


class Items(Base):
    __tablename__ = 'items'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
        'id'          : self.id,
        'user_id'     : self.user_id,
        'name'        : self.name,
        'description' : self.description
            }

engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)

