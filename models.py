# DB FILE FOR CATALOG PROJECT

from sqlalchemy import Column,Integer,String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()

secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    # children = relationship("Items")
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id'           : self.id,
        'username'     : self.username,
        'email'        : self.email,
        'password_hash': self.password_hash
            }

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id

class Items(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id') )
    name = Column(String)
    description = Column(String)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id'          : self.id,
        'user_id'     : self.user_id,
        'name'        : self.name,
        'description' : self.description
            }

engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)