import webapp2
import wsgiref.handlers

from app.views import *


app = webapp2.WSGIApplication([
    webapp2.Route('/', handler=MainHandler, name='home'),
    webapp2.Route('/newpost', handler=NewPost, name='newpost'),
    webapp2.Route('/post/<blog_id>', handler=PostPermaLink, name='blog_post'),
    webapp2.Route('/signup', handler=SignUp, name='signup'),
    webapp2.Route('/welcome', handler=WelcomeHandler, name='welcome'),
    webapp2.Route('/login', handler=LoginHandler, name='login'),
    webapp2.Route('/logout', handler=LogoutHandler, name='logout'),
    webapp2.Route('/editpost/<blog_id>', handler=EditPost, name='editpost'),
    webapp2.Route('/deletepost/<blog_id>', handler=DeletePost,
                  name='deletepost'),
    webapp2.Route('/likepost/<blog_id>', handler=LikePost, name='likepost')
], debug=True)


def main():
    wsgiref.handlers.CGIHandler().run(app)
