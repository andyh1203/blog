import hashlib
import random
import string
from google.appengine.ext import db


class BlogPost(db.Model):
    subject = db.StringProperty()
    blog_content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty()
    likes = db.IntegerProperty()


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_username(cls, username):
        u = User.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, password, email=None):
        hased_password = make_pw_hash(username, password)
        u = User(username=username,
                 password=hased_password,
                 email=email)
        return u

    @classmethod
    def by_id(cls, user_id):
        return User.get_by_id(user_id)

    @classmethod
    def login(cls, username, password):
        u = cls.by_username(username)
        if u and valid_pw(username, password, u.password):
            return u


def make_salt(length=5):
    return ''.join(random.choice(string.ascii_lowercase +
                                 string.ascii_uppercase)
                   for _ in range(length))


def make_pw_hash(username, password, salt=None):
    if salt is None:
        salt = make_salt()
    h = hashlib.sha256(username + password + salt).hexdigest()
    return "{0},{1}".format(salt, h)


def valid_pw(username, password, h):
    salt = h.split(',')[0]
    return make_pw_hash(username, password, salt) == h
