import webapp2
import jinja2
import os
import hashlib
import hmac
from google.appengine.ext import db
from google.appengine.api import memcache
import re
from string import letters
import random
import json
import time
import logging

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates'))) 



def render_str(template, **params):
    t = jinja_environment.get_template(template)
    return t.render(params)


# render and write html
class BlogHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def render_str(self, template, **params):
        return render_str(template, **params)
        
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def notfound(self):
        self.error(404)
        self.write('<h1>404: Not Found. That page does not exist.</h1>')
        self.write('<h3>...or some kind of other error</h3>')

    def login(self, user):
        user_id = str(user.key().id())
        new_cookie_val = make_secure_id_hash(user_id)
        self.response.headers['Content-Type'] = 'text/plain'   
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
        memcache.set(user_id, user)


def blog_key(name = 'default'):
    return db.Key.from_path('blog', name)
    

class Page(db.Model):
    content = db.TextProperty()
    path = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    page_number = db.IntegerProperty()
    
    def render(self):
        self._render_text = self.content #.replace('\n', '<br>')
        return render_str("page.html", p=self)
        
    
class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.TextProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def get_by_id(cls, user_id):
        key = db.Key.from_path('User', int(user_id), parent=blog_key())
        return db.get(key)
        #return User.get_by_id(uid, parent=blog_key())

    @classmethod
    def get_by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u


def get_user(user_id_cookie_str):
    if user_id_cookie_str:
        user_id = check_secure_id_hash(user_id_cookie_str)
        if user_id:
            user = memcache.get(user_id)
            if not user:
                logging.error("\nError in get_user, User.get_by_id\n")
            else:
                return user


def get_username(user_id_cookie_str):
    user = get_user(user_id_cookie_str)
    if user:
        return user.username

    
# path: /blog/welcome
class Welcome(BlogHandler):
    def get(self, arg=None):
        path = '/blog/welcome'
        path_hash = make_secure_id_hash(path)
        self.response.headers.add_header('Set-Cookie', 'prev_page=%s; Path=/' % path_hash)
    
        username = get_username(self.request.cookies.get('user_id'))
        if username:
            content = get_most_recent_page_content(path)
            self.render('welcome.html', page_content=content, logged_in_username=username, editpage=path, historypage=path)
        else:
            self.redirect('/blog/signup')
        
   
def get_previous_page(prev_page_path):
    if prev_page_path:
        return prev_page_path[:prev_page_path.find('-')]
        
# path: /blog/logout      
class Logout(BlogHandler):
    def get(self):
        user_id = self.request.cookies.get('user_id')
        if user_id:
            memcache.delete(user_id)
            self.response.headers['Content-Type'] = 'text/plain'   
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
            
        prev_page_path = get_previous_page(self.request.cookies.get('prev_page'))
        if prev_page_path:
            self.redirect(prev_page_path)
        else:
            #self.redirect('/blog/login')
            self.redirect('/blog')
            
  
# path: /blog/login
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        if not valid_username(username):
            error = 'Please enter a valid Username'
            #self.render("login-form.html", username=username, error_username=error)
            self.writeJsonAjaxResponse("error", error)
            
        elif not valid_password(password):
            error = 'Please enter a valid Password'
            #self.render("login-form.html", username=username, error_password=error)
            self.writeJsonAjaxResponse("error", error)
            
        else:
            query = "select * from User where username='%s'" % username
            user = db.GqlQuery(query).get()
            if not user:
                error = 'Username does not exist'
                #self.render("login-form.html", error_username=error)
                self.writeJsonAjaxResponse("error", error)
                
            elif not check_secure_pw_hash(password, user.pw_hash):
                error = 'Invalid password'
                #self.render("login-form.html", error_password=error)
                self.writeJsonAjaxResponse("error", error)
                
            else:
                self.login(user)
                prev_page_path = get_previous_page(self.request.cookies.get('prev_page'))
                '''if prev_page_path:
                    self.redirect(prev_page_path)
                else:
                    self.redirect('/blog/welcome')'''
                self.writeJsonAjaxResponse("success", prev_page_path)
                

    # write a resonse in json form       
    def writeJsonAjaxResponse(self, status, message):
        self.response.headers['Content-Type'] = 'application/json'
        output = '{'
        output += '"status": "' + status + '",'
        output += '"msg": "' + message + '"'
        output += '}'
        self.write(output)
            
        
# path: /signup
class SignUp(BlogHandler):
    def get(self):
        self.render("signup-form.html")
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        
        if not valid_username(username):
            error = 'Please enter a Username'
            self.render("signup-form.html", username=username, email=email, error_username=error)
        elif not valid_password(password):
            error = 'Please enter a Password'
            self.render("signup-form.html", username=username, email=email, error_password=error)
        elif not verify:
            error = 'Please verify your password here'
            self.render("signup-form.html", username=username, email=email, error_verify=error)
        elif password != verify:
            error = 'Your passwords do not match'
            self.render("signup-form.html", username=username, email=email, error_verify=error)
            
        else:
            query = "select * from User where username='%s'" % username
            q = db.GqlQuery(query)
            if q.count() > 0:
                error = 'Username already exists'
                self.render("signup-form.html", username=username, email=email, error_username=error)
            else:
                user = User(parent=blog_key(), username=username, pw_hash=make_secure_pw_hash(password), email=email)
                user.put()
                self.login(user)
                prev_page_path = get_previous_page(self.request.cookies.get('prev_page'))
                if prev_page_path:
                    self.redirect(prev_page_path)
                else:
                    self.redirect('/blog/welcome')


######### cookies handler lesson

secret = 'ThisIsASecretHashSalt'

def hash_str(pw, salt=''):
    #return hashlib.md5(s).hexdigest()
    return hmac.new(secret, pw+salt).hexdigest()
    
def make_secure_pw_hash(pw, salt=None):
    if not salt:
        salt = make_salt()
    return '%s-%s' % (salt, hash_str(pw, salt=salt))
    
def check_secure_pw_hash(pw, hash_val):
    salt = hash_val.split('-')[0]
    if hash_val == make_secure_pw_hash(pw, salt=salt):
        return salt
    
def make_secure_id_hash(user_id):
    return '%s-%s' % (user_id, hash_str(user_id))
    
def check_secure_id_hash(hash_val):
    user_id = hash_val.split('-')[0]
    if hash_val == make_secure_id_hash(user_id):
        return user_id
    
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


def getPostString(post):
    return """{"content":"%s", "created":"%s", "last_modified":"%s", "subject":"%s"}""" % (post.content, post.created, post.last_modified, post.subject) # strftime("%b %d, %Y")


def get_most_recent_page_content(path):
    pages = memcache.get(path)
    if pages:
        return pages[0].content


def set_cache_with_time(key, value):
    value = (value, time.time())
    memcache.set(key, value)
    return value



def get_blog_posts(newpost=None):
    key = "posts"
    value = memcache.get(key)
    
    if value is None:
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        posts = list(posts)
        value = set_cache_with_time(key, posts)
        
    elif newpost:
        posts = value[0]
        posts.insert(0, newpost)
        if len(posts) == 11:
            posts.pop()
        value = set_cache_with_time(key, posts)
    
    return value[0], int(time.time()-value[1])
        

# path: /blog/?
class BlogFront(BlogHandler):
    def get(self):
        path = '/blog'
        path_hash = make_secure_id_hash(path)
        self.response.headers.add_header('Set-Cookie', 'prev_page=%s; Path=/' % path_hash)
    
        username = get_username(self.request.cookies.get('user_id'))
        posts, queried = get_blog_posts()
        content = get_most_recent_page_content(path)
        self.render('front.html', page_content=content, posts=posts, queried=queried, logged_in_username=username, editpage=path, historypage=path)



# path: /blog/?.json
class BlogFrontJson(BlogHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'application/json'
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        output = '['
        for post in posts:
            output += getPostString(post) + ','
        output = output[:-1]
        output += ']'
        self.write(output)


def get_permalink_post(post_id, update=False):
    key = str(post_id)
    value = memcache.get(key)
    
    if value is None or update:
        dbkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(dbkey)
        value = set_cache_with_time(key, post)
        
    return value[0], int(time.time()-value[1])


# path: /blog/post_id        
class PostPage(BlogHandler):
    def get(self, post_id):
        path = '/blog/%s' % post_id
        path_hash = make_secure_id_hash(path)
        self.response.headers.add_header('Set-Cookie', 'prev_page=%s; Path=/' % path_hash)
        
        post, queried = get_permalink_post(post_id)
        username = get_username(self.request.cookies.get('user_id'))
        
        content = get_most_recent_page_content(path)
        
        if not post:
            self.notfound()
            return
        
        self.render("permalink.html", post=post, page_content=content, queried=queried, logged_in_username=username, editpage=path, historypage=path)
        
        
# path: /blog/\d+.json   
class PostPageJson(BlogHandler):
    def get(self, post_id):
        self.response.headers['Content-Type'] = 'application/json'
        post, queried = get_permalink_post(post_id)
        
        if not post:
            self.notfound()
            return
            
        self.write(getPostString(post))



# path: /blog/newpost
class NewPost(BlogHandler):
    path = '/blog/newpost'
    page_content = None
    def get(self):
        path_hash = make_secure_id_hash(self.path)
        self.response.headers.add_header('Set-Cookie', 'prev_page=%s; Path=/' % path_hash)
        
        username = get_username(self.request.cookies.get('user_id'))
        if username:
            self.page_content = get_most_recent_page_content(self.path)
            self.render('newpost.html', page_content=self.page_content, logged_in_username=username, editpage=self.path, historypage=self.path)
        else:
            #self.redirect('/blog/login')
            self.redirect('/blog')
               
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        username = get_username(self.request.cookies.get('user_id'))
        
        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put()
            # update cache with new post
            get_blog_posts(newpost=p)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Please enter a subject and a blog post'
            self.render('newpost.html', page_content=self.page_content, subject=subject, content=content, error=error, logged_in_username=username, editpage=self.path, historypage=self.path)

     
       
def update_pages(page, path):
    # get pages at given path
    pages = memcache.get(path)
    
    # insert most recent page
    if pages:
        pages.insert(0, page)
    else:
        pages = [page]
    memcache.set(path, pages)
       
  
       
# path: '/_edit' + PAGE_RE  
class EditPage(BlogHandler):
    content = ''
    def get(self, path=''):
        thispage = '/_edit/'
        #self.path = check_secure_id_hash(self.request.cookies.get('prev_page'))
        username = get_username(self.request.cookies.get('user_id'))
        if username:
            pages = memcache.get(path) 
            if pages:
                self.content = pages[0].content
                self.render('edit.html', logged_in_username=username, content=self.content)
            else:
                self.render('edit.html', logged_in_username=username)
        else:
            #self.redirect('/blog/login')
            self.redirect('/blog')
            
    def post(self, path=''):
        content = self.request.get('content')               
        if content != self.content or self.content is None:
            page = Page(parent=blog_key(), content=content, path=path)
            page.put()
            # update cache with new post
            update_pages(page, path)
        self.redirect(path)
        
        
        
# path: PAGE_RE       
class NewWikiPage(BlogHandler):
    def get(self, path):
        path_hash = make_secure_id_hash(path)
        self.response.headers.add_header('Set-Cookie', 'prev_page=%s; Path=/' % path_hash)
    
        username = get_username(self.request.cookies.get('user_id'))

        # check if page has been already created
        content = get_most_recent_page_content(path)
        if content:
            self.render('newpage.html', page_content=content, logged_in_username=username, editpage=path, historypage=path)
        elif username:
            self.redirect('/_edit' + path)       
        else:
            #self.redirect('/blog/login')
            self.redirect('/blog')
       
       
       
#path: /_view/(\W+)
class ViewPage(BlogHandler):
    def get(self, path=''):
        username = get_username(self.request.cookies.get('user_id'))
        print 'PATH', path
        index = path.rfind('/')
        
        if index > -1 and index < len(path)-1:
            page_num = int(path[index+1:])
            pagepath = path[:index]
            pages = memcache.get(pagepath)
            
            if page_num < len(pages):
                self.render('newpage.html', page_content=pages[page_num].content, logged_in_username=username)
                return
        self.notfound()
        

#path: /_revert/(\W+)
class RevertPage(BlogHandler):
    def get(self, path=''):
        print 'PATH', path
        index = path.rfind('/')
        
        if index > -1 and index < len(path)-1:
            page_num = int(path[index+1:])
            pagepath = path[:index]
            pages = memcache.get(pagepath)
            
            if page_num < len(pages):
                revertpage = pages.pop(page_num)
                pages.insert(0, revertpage)
                memcache.set(pagepath, pages)
                self.redirect(pagepath)
                return
        self.notfound()

        
     
     
       
#path: /_history/(\W+)
class History(BlogHandler):
    def get(self, path=''):
        username = get_username(self.request.cookies.get('user_id'))
        #prev_page = check_secure_id_hash(self.request.cookies.get('prev_page'))
        
        pages = memcache.get(path)
        
        if not pages or len(pages) == 0:
            self.render("newpage.html", page_content='<p class="post-title">This page has not been edited</p>', logged_in_username=username)
            return
        
        for i in xrange(len(pages)):
            pages[i].page_number = i
            
        self.render("history.html", pages=pages, logged_in_username=username)


       
# flush memcache memory       
# path: /blog/flush
class FlushCache(BlogHandler):
    def get(self):
        memcache.flush_all()
        prev_page_path = get_previous_page(self.request.cookies.get('prev_page'))
        if prev_page_path:
            self.redirect(prev_page_path)
        else:
            self.redirect('/blog')
          
          
          

# path: /
class MainPage(BlogHandler):
    def get(self):
        path = '/'
        username = get_username(self.request.cookies.get('user_id'))
        page_content = get_most_recent_page_content(path)
        
        self.response.headers['Content-Type'] = 'text/plain' 
        visit_cookie_str = self.request.cookies.get('visits')
        visits = 0
        if visit_cookie_str:
            cookie_val = check_secure_id_hash(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_cookie_val = make_secure_id_hash(str(visits))
        
        self.response.headers.add_header('Set-Cookie', 'visits=%s; Path=/' % new_cookie_val)
        self.redirect('/blog')
        
    '''    
    def post(self):
        txt = self.request.get('text').encode('rot13')
        template_values = {'string':txt.strip()}
        self.render("front.html", template_values, logged_in_username=username)
    '''
        
       
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/welcome(/\w*)?', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/signup', SignUp),
                               (r'/blog/?', BlogFront),
                               (r'/blog/flush', FlushCache),
                               (r'/blog/(\d+)', PostPage),
                               (r'/_view' + PAGE_RE, ViewPage),
                               (r'/_revert' + PAGE_RE, RevertPage),
                               (r'/_history' + PAGE_RE, History),
                               (r'/blog/?\.json', BlogFrontJson),
                               (r'/blog/(\d+)\.json', PostPageJson),
                               ('/blog/newpost', NewPost),
                               ('/_edit/?' + PAGE_RE, EditPage),
                               (PAGE_RE, NewWikiPage)
                               ],
                               debug = True)






# print request server information
#self.response.headers['Content-Type'] = 'text/plain'
#self.response.out.write(self.request)

# change pages
#self.redirect('/testform') 
