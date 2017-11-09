#! --shebang
# DB FILE FOR CATALOG PROJECT
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import random
import string
Base = declarative_base()
secret_key = ''.join(
    random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


# create User table
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)

    # serialize property to return information in JSON format
    @property
    def serialize(self):
        return {
               'id': self.id,
               'username': self.username,
               'email': self.email,
               }


# create Items table
class Items(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # serialize property to return data in JSON format
    @property
    def serialize(self):
        return {
               'id': self.id,
               'user_id': self.user_id,
               'name': self.name,
               'description': self.description
               }


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
