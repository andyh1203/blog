import webapp2
import datetime
import re
import hmac
import jinja2

from models import BlogPost, User
from os.path import dirname, join
from config import SECRET_KEY


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
SECRET = SECRET_KEY

template_dir = join(dirname(dirname(__file__)), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
jinja_env.globals['url_for'] = webapp2.uri_for


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def set_cookie(self, name, val):
        cookie = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '{0}={1}; Path=/'.format(name, cookie)
                                         )

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        cookie = self.request.cookies.get(name)
        return cookie and check_secure_val(cookie)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.by_id(int(user_id))


class MainHandler(Handler):

    def get(self):
        blog_posts = BlogPost.all().order('-created')
        self.render("main_page.html", blog_posts=blog_posts, user=self.user)


class EditPost(Handler):

    def get(self, blog_id):
        b = BlogPost.get_by_id(int(blog_id))
        self.render("edit_post.html", b=b)

    def post(self, blog_id):

        b = BlogPost.get_by_id(int(blog_id))
        b.subject = self.request.get("subject")
        b.blog_content = self.request.get("blog_content").replace('\n', '<br/>'
                                                                  )

        if b.subject and b.blog_content:
            b.created = datetime.datetime.now()
            b.put()
            self.redirect('/')
        else:
            error = "subject and content, please!"
            self.render("edit_post.html", error=error, b=b)


class NewPost(Handler):

    def render_new_post(self, subject="", blog_content="", error=""):
        self.render("new_post.html", subject=subject,
                    blog_content=blog_content,
                    error=error,
                    user=self.user)

    def get(self):
        if not self.user:
            self.redirect('/signup')
        else:
            self.render_new_post()

    def post(self):
        params = {}

        subject = self.request.get("subject")
        blog_content = self.request.get("blog_content").replace('\n', '<br/>')

        params['subject'] = subject
        params['blog_content'] = blog_content

        if subject and blog_content:
            b = BlogPost(subject=subject, blog_content=blog_content,
                         author=self.user.username, likes=0)
            b.put()
            self.redirect('/post/{0}'.format(b.key().id()))
        else:
            params['error'] = "subject and content, please!"
            self.render_new_post(**params)


class PostPermaLink(Handler):
    def get(self, blog_id):
        b = BlogPost.get_by_id(int(blog_id))
        self.render("blog_permalink.html", b=b)


class SignUp(Handler):
    def write_form(self, username="", password="", verify="",
                   email="", username_error="", password_error="",
                   verify_error="", email_error=""):

        self.render("sign_up.html",
                    username=username,
                    password=password,
                    verify=verify,
                    email=email,
                    username_error=username_error,
                    password_error=password_error,
                    verify_error=verify_error,
                    email_error=email_error,
                    user=self.user)

    def get(self):
            self.write_form()

    def post(self):
        has_error = False
        params = {}
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        params['username'] = username
        params['email'] = email
        valid_user = validate_username(username)
        if not valid_user:
            params['username_error'] = "That's not a valid username."
            has_error = True

        valid_password = validate_password(password)
        if not valid_password:
            params['password_error'] = "That wasn't a valid password."
            has_error = True

        if email:
            valid_email = validate_email(email)
            if not valid_email:
                params['email_error'] = "That's not a valid email."
                has_error = True

        verified_password = verify_password(password, verify)
        if not verified_password:
            params['verify_error'] = "Your passwords didn't match."
            has_error = True

        u = User.by_username(username)
        if u:
            params['username_error'] = "That user already exists."
            has_error = True

        if not has_error:
            if email:
                u = User.register(username, password, email)
            else:
                u = User.register(username, password)
            u.put()
            self.login(u)
            self.redirect('/welcome')
        else:
            self.write_form(**params)


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render("welcome.html", username=self.user.username,
                        user=self.user)
        else:
            self.redirect('/signup')


class LoginHandler(Handler):

    def render_login(self, error=""):
        return self.render("login.html", error=error, user=self.user)

    def get(self):
        self.render_login()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            error = 'Invalid login'
            self.render_login(error=error)


class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class DeletePost(Handler):
    def get(self, blog_id):
        b = BlogPost.get_by_id(int(blog_id))
        b.delete()
        self.redirect('/')


class LikePost(Handler):
    def get(self, blog_id):
        b = BlogPost.get_by_id(int(blog_id))
        b.likes += 1
        b.put()
        self.redirect('/')


def validate_username(username):
    return USER_RE.match(username)


def validate_password(password):
    return PASSWORD_RE.match(password)


def validate_email(email):
    return EMAIL_RE.match(email)


def verify_password(password, verify):
    return password == verify


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "{0}|{1}".format(s, hash_str(s))


def check_secure_val(h):
    if h == make_secure_val(h.split('|')[0]):
        return h.split('|')[0]
