#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
基于django的新浪微博oauth views
需要django的session支持
"""
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch
import urllib
from google.appengine.ext.webapp import RequestHandler, WSGIApplication
from models import GRUser
from google.appengine.ext import db
from wsgiref.handlers import CGIHandler
from twitter_oauth_handler import OAuthRequestToken, OAuthAccessToken
from weibopy import OAuthHandler, WeibopError
from weibopy import oauth
from weibopy.api import API
from uuid import uuid4
import logging
import re

try:
    from config import OAUTH_APP_SETTINGS  #you need to specify the consumer_key and consumer_secret to use the oAUTH API
except:
    pass

SERVICE = 'weibo'
CALLBACK_URL = 'http://reader2twitter.appspot.com/oauth/weibo/callback'


def create_uuid():
    return 'id-%s' % uuid4()

class WebOAuthHandler(OAuthHandler):
    
    def get_authorization_url_with_callback(self, callback, signin_with_twitter=False):
        """Get the authorization URL to redirect the user"""
        # get the request token
        self.request_token = self._get_request_token()

        # build auth request and return as url
        if signin_with_twitter:
            url = self._get_oauth_url('authenticate')
        else:
            url = self._get_oauth_url('authorize')
        request = oauth.OAuthRequest.from_token_and_callback(
            token=self.request_token, callback=callback, http_url=url
        )
        return request.to_url()

    def set_cookie(self, value):
        self.handler.response.headers.add_header(
            'Set-Cookie', 
            '%s=%s; path=%s; expires="Fri, 31-Dec-2021 23:59:59 GMT"' %
            ('oauth.%s' % SERVICE, value, '/')
            )

    def get_cookie(self):
        if self.handler:
            return self.handler.request.cookies.get(
                'oauth.%s' % SERVICE, ''
                )

    def expire_cookie(self):
        self.handler.response.headers.add_header(
            'Set-Cookie', 
            '%s=; path=%s; expires="Fri, 31-Dec-1999 23:59:59 GMT"' %
            ('oauth.%s' % SERVICE, '/')
            )


def _get_referer_url(request):
    referer_url = request.META.get('HTTP_REFERER', '/')
    host = request.META['HTTP_HOST']
    if referer_url.startswith('http') and host not in referer_url:
        referer_url = '/' # 避免外站直接跳到登录页而发生跳转错误
    return referer_url

def _oauth(handler = None):
    """获取oauth认证类"""
    auth_client = WebOAuthHandler(OAUTH_APP_SETTINGS['weibo']['consumer_key'], OAUTH_APP_SETTINGS['weibo']['consumer_secret'], handler = handler)
    if handler:
        if auth_client.get_cookie():
            access_token = OAuthAccessToken.get_by_key_name(auth_client.get_cookie())
            if access_token:
                auth_client.setToken(access_token.oauth_token, access_token.oauth_token_secret)
    return auth_client

class SinaLogin(RequestHandler):
    def get(self):
        auth_client = _oauth()
        auth_url = auth_client.get_authorization_url_with_callback(CALLBACK_URL)
        OAuthRequestToken(service = SERVICE, oauth_token = auth_client.request_token.key, oauth_token_secret = auth_client.request_token.secret).put()
        self.redirect(auth_url)
         
class SinaCallback(RequestHandler):
    def get(self):
        verifier = self.request.get("oauth_verifier", "")
        oauth_token = self.request.get("oauth_token", "")
        auth_client = _oauth(self)
        request_token = OAuthRequestToken.all().filter('oauth_token =', oauth_token).filter('service =', SERVICE).fetch(1)[0]
        auth_client.set_request_token(request_token.oauth_token, request_token.oauth_token_secret)
        access_token = auth_client.get_access_token(verifier)
        key_name = create_uuid()
        username = auth_client.get_username()
        old = OAuthAccessToken.all().filter(
                'specifier =', username).filter(
                'service =', SERVICE)
        if old.count() > 0:
            db.delete(old)
        OAuthAccessToken(key_name=key_name, service=SERVICE, oauth_token = access_token.key, oauth_token_secret = access_token.secret, specifier = username).put()         
        auth_client.set_cookie(key_name)
        #self.response.out.write(username)
        self.redirect("/oauth/weibo/newuser")

class SinaTest(RequestHandler):
    def get(self):
        auth_client = _oauth(self)
        if auth_client.get_cookie():
            #api = API(auth_client)
            #api.update_status("测试新浪微博oAuth API")
            self.response.out.write("ok")

def update_weibo(gruser, message):
    access_token = OAuthAccessToken.all().filter("specifier = ",gruser.username).fetch(1)[0]
    auth_client = _oauth()
    auth_client.setToken(access_token.oauth_token, access_token.oauth_token_secret)
    api = API(auth_client, source = "Reader2微博")
    api.update_status(message)

class SinaLogout(RequestHandler):
    def get(self):
        """用户登出，直接删除access_token"""
        auth_client = _oauth(self)
        auth_client.expire_cookie()
        self.redirect("/weibo/greader")

class NewSinaUser(RequestHandler):
    """Demo Twitter App."""
 
    def get(self):
        auth_client = _oauth(self)
        if not auth_client.get_cookie():
            self.redirect('/')
            return
        
        username =  auth_client.get_username()
        if not username:
          self.response.out.write('Error occured when conmunicating with Twitter. Please <a href="/">try again</a>.')
        else:
          gruser = GRUser.get_by_key_name('Key_Weibo_%s' % username)
          if not gruser:
              gruser = GRUser(key_name='Key_Weibo_'+username,username = username, oauth = True)
              gruser.put()
              logging.debug("New Weibo-Login user.")
              logging.info(username)
          else:
              gruser.oauth = True
              gruser.put()
          self.redirect('/weibo/greader.settings')

class Weibo(RequestHandler):
  """Debug handler for simulating events."""
  def get(self):
    auth_client = _oauth(self)
    if not auth_client.get_cookie():
        self.response.out.write('请<a href="/oauth/weibo/login">登录</a>')   
        return
    try:
        username =  auth_client.get_username()
    except:
        self.redirect('/oauth/weibo/login')
        return
    gruser = GRUser.get_by_key_name('Key_Weibo_%s' % username)
    template_value = {}
    if gruser:
        mygruser = {}
        mygruser["username"]=gruser.username
        mygruser["format"]=gruser.format
        mygruser["bitlykey"]=gruser.bitlykey
        mygruser["bitlylogin"]=gruser.bitlylogin        
        mygruser["synctype"]={}
        mygruser["readerid"]=""
        if gruser.topic:
            mygruser["readerid"] = gruser.topic.replace("http://www.google.com/reader/public/atom/user/","")
            mygruser["readerid"] = mygruser["readerid"].replace("/state/com.google/broadcast","")
        if not gruser.synctype:
            mygruser["synctype"] = {"all":"checked","comment":"","Note":""}    
        elif gruser.synctype == "all":
            mygruser["synctype"] = {"all":"checked","comment":"","Note":""}
        elif gruser.synctype == "comment":
            mygruser["synctype"] = {"all":"","comment":"checked","Note":""}
        else:
            mygruser["synctype"] = {"all":"","comment":"","Note":"checked"}       
        template_value = {"gruser":mygruser}         
    self.response.out.write(template.render('syncweibo.html', template_value))
  def post(self):
    auth_client = _oauth(self)
    if auth_client.get_cookie():
        username = auth_client.get_username()
        logging.info(username)
        grid = self.request.get("grid")
        if re.search(r"\d*",grid).group():
            topic = "http://www.google.com/reader/public/atom/user/%s/state/com.google/broadcast" % grid
            issync = self.request.get("mode")
            gruser = GRUser.get_by_key_name('Key_Weibo_%s' % username)
            if issync == "subscribe":
                synctype = self.request.get("synctype")
                logging.info(synctype)
                if gruser:
                    gruser.topic = topic
                    gruser.synctype = synctype
                    gruser.unsubscribe = False
                    gruser.put()
                else:
                    logging.info("新用户")
                    gruser = GRUser(key_name='Key_Weibo_'+username,username = username,topic = topic)
                    gruser.put()
            elif gruser:
                logging.debug("用户退订")
                logging.debug(gruser.username)
                gruser.unsubscribe = True
                gruser.put()  
                return                
            payload = {"hub.mode":issync,"hub.verify":"sync","hub.callback":"http://reader2twitter.appspot.com/subscriber","hub.topic":topic}
            payload= urllib.urlencode(payload)
            url = "http://pubsubhubbub.appspot.com/subscribe"
            try:
                result = urlfetch.fetch(url, payload=payload, method=urlfetch.POST)#, headers=headers)
                logging.info(result.status_code)
                if result.status_code == 204:  
                    logging.info("%s success" % issync)  
                    if issync == "unsubscribe":
                        self.response.out.write('同步已被停止。如果有问题，请联系<a href="http://t.sina.com.cn/kangye">开发者</a>。')
                    else:
                        self.response.out.write("同步已设置成功。<a href=\"javascript:var%20b=document.body;var%20GR________bookmarklet_domain='http://www.google.com';if(b&&!document.xmlVersion){void(z=document.createElement('script'));void(z.src='http://www.google.com/reader/ui/link-bookmarklet.js');void(b.appendChild(z));}else{}\">点击测试</a>")
                else:
                    logging.info("向hub订阅Publisher失败")
                    self.response.out.write('请<a href="/weibo/greader.settings">重试</a>')
            except:
                logging.info("和hub连接失败")
                self.response.out.write('请<a href="/weibo/greader.settings">重试</a>')
        else:
            logging.info("google reader id格式错误")
            self.response.out.write('请试用Google Reader<b>数字</b>ID，<a href="/weibo/greader.settings">重试</a>')
    else:
        logging.info("没有oauth认证")
        self.response.out.write('请<a href="/oauth/weibo/login">登录</a>')

class WeiboIndex(RequestHandler):
  """Debug handler for simulating events."""
  def get(self):
    auth_client = _oauth(self)
    if auth_client.get_cookie():
        self.redirect("/weibo/greader.settings")
    else:
        self.response.out.write(template.render('weiboindex.html', {}))

def main():

    application = WSGIApplication([
       ('/oauth/weibo/login', SinaLogin),
       ('/oauth/weibo/logout', SinaLogout),
       ('/oauth/weibo/callback', SinaCallback),
       ('/oauth/weibo/newuser', NewSinaUser),
       ('/weibo/greader.settings', Weibo),
       ('/weibo/greader', WeiboIndex),
       ('/oauth/weibo/test', SinaTest)
       ], debug=True)

    CGIHandler().run(application)

if __name__ == '__main__':
    main()
