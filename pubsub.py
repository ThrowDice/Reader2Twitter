#coding=utf-8
#!/usr/bin/env python
#
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from google.appengine.ext.webapp import template
from django.utils import simplejson as json
import models
from models import GRUser
from models import SomeUpdate
import feedparser
import twitter_oauth_handler
import sina_oauth_handler
import bitly
import hashlib
import logging
from google.appengine.ext import ereporter
import random
import urllib
import urllib2
import base64
import time
import datetime     
import re
import uuid
import wsgiref.handlers
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.api.labs import taskqueue
from google.appengine.api import memcache
from google.appengine.ext import deferred
from google.appengine.api import urlfetch
from google.appengine.api.urlfetch_errors import *

UPDATE_CLEANUP_BATCH_SIZE = 100
UPDATE_LIVE_TIME = 97
consumer_key = '1935597329' # 设置你申请的appkey
consumer_secret = '7008f8920d5a7e92101d408ac468b0e7' # 设置你申请的appkey对于的secret

class UpdateStat(db.Model):
    """UPDATE STATISTICS.

    Key name will be a hash of the feed source and item ID.
    """
    counter = db.IntegerProperty(default = 0)
    
    @staticmethod
    def update_today_stat(type,counter):
        """update today's stat"""
        today = str(datetime.date.today())
        tdkeyname = "%s%s" % (type,today)
        today_stat = UpdateStat.get_or_insert(tdkeyname)
        today_stat.increase(counter)

    @staticmethod
    def recent_stats_graph_url():
        """using chart api to show recent 7 days stat graph"""
        grs = UpdateStat.recent_stats("GoogleReader",7)
        gbs = UpdateStat.recent_stats("GoogleBuzz",7)
        grs_list = ','.join([str(gr.counter) for gr in grs])
        gbs_list = ','.join([str(gb.counter) for gb in gbs])
        return 'http://chart.apis.google.com/chart?cht=bvs&chs=400x250&chd=t:%s|%s&chco=4d89f9,c6d9fd&chbh=20&chds=0,10000&chm=D,76A4FB,1,0,3|N,FF0000,-1,-1,10|N,000000,0,,12,,c|N,000000,1,,12,,c' % (grs_list,gbs_list)

    @staticmethod
    def recent_stats(type,number):
        """#number past stat before today"""
        return [UpdateStat.get_stat(type,i) for i in reversed(range(0,number))]

    @staticmethod
    def get_stat(type,offset):
        """get #offset day stat"""
        return UpdateStat.get_or_insert("%s%s" % (type,str(datetime.date.today()+datetime.timedelta(days=-offset))))


    def increase(self,counter):
        """Increase the counter by given counter"""
        db.run_in_transaction(increment_counter, self.key(), 1)

def increment_counter(key, amount):
    obj = db.get(key)
    obj.counter += amount
    obj.put()

class PubTwitter(webapp.RequestHandler):
    """Handles feed input and subscription"""
    def get(self):
        username = self.request.get("username")
        message  = self.request.get("message").encode('utf-8')
        service  = self.request.get("service")
        logging.info('Task added: repub '+username+"'s tweet in "+service)
        logging.info(message)
        try:
            if username == "yishake" or username == 'P3t3rU5':
                return
            gruser = is_user(username)
            if not gruser:
                return
            if gruser.oauth:
                token = get_token_by_username(gruser.username)
                client = twitter_oauth_handler.OAuthClient('twitter', self)
                client.token = token
                client.post("/statuses/update",status = message)
            else:
                basestring = gruser.basestring
                pub_to_twitter_by_basestring(basestring,message)
            self.response.set_status(200)
            self.response.out.write("OK")
        except Exception,e:
            if "Could not authenticate you." in str(e):
                logging.info("twitter auth is invalid")
                if service == 'GR2T':
                    gruser.topic = ''
                    gruser.unsubscribe = True
                    gruser.put()
                    logging.info('Stop %s % service' % (username,service))
                elif service == 'GB2T':
                    gruser.buzztopic = ''
                    gruser.put()
                    logging.info('Stop %s % service' % (username,service))
                return      
            self.response.set_status(200)
            self.response.out.write("OK")
            logging.debug(e)            
    post = get
 
def logging_now():
	now = datetime.datetime.now()+datetime.timedelta(hours=8)
	logging.info(now)

class Feedr(webapp.RequestHandler):
    """Handles feed input and subscription"""

    def get(self):
        # Just subscribe to everything.
        self.response.out.write(self.request.get('hub.challenge'))
        self.response.set_status(200)
        logging.info("subscribed %s" % self.request.get('hub.topic'))
  
    def post(self):
        logging_now()
        body = self.request.body.decode('utf-8')
        logging.info('Post body is %d characters', len(body))

        logging.info(self.request.body)
        data = feedparser.parse(self.request.body)
        for entry in data.entries:
          if hasattr(entry, 'content'):
              entry_id = entry.id
              if entry.has_key("summary_detail"):
                  content = entry.summary_detail.value
              else:
                  content = entry.content[0].value
              link = entry.get('link', '')
              title = entry.get('title', '')
          else:
              content = entry.get('description', '')
              title = entry.get('title', '')
              link = entry.get('link', '')
              entry_id = (entry.get('id', '') or link)
          logging.info(entry_id)
          logging.info(title)
          logging.info(link)
          
def buzz_date(e):
    if hasattr(e,"published"):
        return e.published
    elif hasattr(e,"updated"):
        return e.updated
    else:
        return

class BuzzPuSH(webapp.RequestHandler):
  """Handles feed input and subscription"""

  def get(self):
    # Just subscribe to everything.
    self.response.out.write(self.request.get('hub.challenge'))
    self.response.set_status(200)
    logging.info("subscribed %s" % self.request.get('hub.topic'))

  def post(self):
    """handle notification of buzz update from hub"""
    body = self.request.body
    logging.debug(body)
    body_len = len(body)
    logging.info(body_len)
    if body_len < 0:
      logging.debug('Added to queue for quick response.')
      buzz_queue = taskqueue.Queue("buzz2twitter")  
      task = taskqueue.Task(url = '/buzzpush-queue', payload = urllib.quote(body))
      buzz_queue.add(task)
      self.response.set_status(200)
    else:
      data = feedparser.parse(body)
      buzztopic = data.feed.links[0]["href"]
      if '?' in buzztopic:
        buzztopic = buzztopic[:buzztopic.find('?')]
      logging.info(buzztopic)
      pubsub_topic = models.PubSubTopic.get_or_insert(key_name = buzztopic)
      """
      if not memcache.get(buzztopic):
          memcache.add(buzztopic,"1",3)
      else:
          logging.info("hub notify me two duplicates")
          return
      """
      grusers = get_user_by_buzztopic(buzztopic) #need to change the datastore structure
      if not grusers:
          return
      logging.info(grusers[0].username)
      token = ''
      username = ''
      counter = 0
      logging.info('Found %d entries', len(data.entries))
      logging.debug(body)
      logging.debug(data)
      for entry in data.entries:
          if hasattr(entry, 'content'):
              entry_id = entry.id
              if entry.has_key("summary_detail"):
                  content = entry.summary_detail.value
              else:
                  content = entry.content[0].value
              link = entry.get('link', '')
              title = entry.get('title', '')
          else:
              content = entry.get('description', '')
              title = entry.get('title', '')
              link = entry.get('link', '')
              entry_id = (entry.get('id', '') or link)
          logging.info('Found entry with title = "%s", id = "%s"',title, entry_id)
          if hasattr(entry, 'source'):
            source = entry.source.title
            logging.debug(source)
          else:
            source = ''
          if hasattr(entry, 'point'):
            logging.debug('point: %s' % entry.point)
          #if "from Buzz" in title or "from Mobile" in title or "Google Maps for Mobile" in title or "via buzz@gmail" in title:
          if source == 'Buzz' or source == 'Mobile' or source == 'Posted via buzz@gmail' or "from Buzz" in title or "from Mobile" in title or "Google Maps for Mobile" in title or "via buzz@gmail" in title:
            logging.info(entry)
            #content = content+">"
            logging.debug(link)
            logging.debug(buzztopic)
            my_key_name = 'key_' + hashlib.sha1(buzz_date(entry) + '\n' + buzztopic).hexdigest()
            logging.debug(my_key_name)
            if models.UpdateItem.get_by_key_name(key_names = my_key_name, parent = pubsub_topic):  
                logging.debug("Dupilcates!!!")
                continue
            else:
                counter += 1
                #Use hashed key_name to save query time
                #someupdate = SomeUpdate(key_name=my_key_name)
                #someupdate.put()
                db.put(models.UpdateItem(parent = pubsub_topic, key_name=my_key_name))
            if counter>2:
                continue
            else:
                content = re.sub("<[^>]*>","",content)
                logging.info(buzz_date(entry))
                for gruser in grusers:
                  logging.info(gruser.username)
                  try:
                      link = shorten(link,gruser.bitlylogin,gruser.bitlykey)
                  except:
                      link = link
                  logging.debug("debug link")
                  logging.debug(link)
                  if gruser.buzzlink == 'enable':
                      message = content+" "+link
                      if len(message)>139:
                          if "http://" in content:
                              message = content[:content.find("http://")]+"... "+link
                          else:
                              message = content[:100]+"... "+link
                  else:   
                      message = content
                      if len(message)>139:
                          if "http://" in content:
                              message = content[:content.find("http://")]+"... "+link
                          else:
                              message = content[:100]+"... "+link
                      elif hasattr(entry, 'enclosures'):
                          logging.info("enclosures")
                          for enclosure in entry.enclosures:
                          #    logging.info(enclosure.type)
                              if enclosure.type == "image/jpeg" and enclosure.href.find("http://picasaweb.google.com/")==0:
                                  message = content[:100]+" [pic] "+link
                                  break
                              elif enclosure.type == "text/html" or enclosure.type == "application/x-shockwave-flash":
                                  link = shorten(enclosure.href,gruser.bitlylogin,gruser.bitlykey)
                                  message = content[:100]+"... "+link
                                  break
                  message = message.encode("utf-8")
                  if not gruser.oauth:
                      basestring = gruser.basestring
                      try:
                          logging.info(message)
                          pub_to_twitter_by_basestring(basestring,message)
                      except:
                          return
                  else:
                      client = twitter_oauth_handler.OAuthClient('twitter', self)
                      client.token = get_token_by_username(gruser.username)
                      try:
                          logging.info(message)
                          client.post("/statuses/update",status = message)
                      except Exception,e:
                          logging.debug(e)
      self.response.set_status(200)
      UpdateStat.update_today_stat("GoogleBuzz",counter)
      logging.info("Published %d item(s) to Twitter" % counter)

def buzz_date(e):
    if hasattr(e,"published"):
        return e.published
    elif hasattr(e,"updated"):
        return e.updated
    else:
        return

class InputHandler(webapp.RequestHandler):
  """Handles feed input and subscription"""

  def get(self):
    # Just subscribe to everything.
    self.response.out.write(self.request.get('hub.challenge'))
    self.response.set_status(200)
    logging.info("subscribed %s" % self.request.get('hub.topic'))

  def post(self):
    """handle the update from hub and then pub it to twitter"""
    body = self.request.body
    logging.debug(body)
    data = feedparser.parse(body)  
    logging.debug(data)
    try:
        topic = data.feed.links[1]["href"]          #for hub is the 2nd property
    except:
        topic = data.feed.links[0]["href"]
    pubsub_topic = models.PubSubTopic.get_or_insert(key_name = topic)
    grusers = get_user_by_topic(topic)          #we can use "twitter_username" as the key_name
    if not grusers:
        logging.debug("No user have this topic %s" % topic)
        return                                  #maybe unsubscribe if no user have subscribed the topic
    format = ''
    token = ''
    username = ''
    counter = 0
    logging.info('Found %d entries', len(data.entries))
    for entry in data.entries:
      if hasattr(entry, 'content'):
        # This is Atom.
        entry_id = entry.id
        if entry.has_key("summary_detail"):
            content = entry.summary_detail.value
        else:
            content = entry.content[0].value
        link = entry.get('link', '')
        title = entry.get('title', '')
      else:
        content = entry.get('description', '')
        title = entry.get('title', '')
        link = entry.get('link', '')
        entry_id = entry.get('id', '')
      logging.info('Found entry with title = "%s", id = "%s"',title, entry_id)
      #my_key_name  is a unique key_name for a update
      my_key_name = 'key_' + entry_id#hashlib.sha1(link + '\n' + entry_id +topic).hexdigest()
      logging.debug(my_key_name)
      #if not is_article_exist(my_key_name,topic,link):      #is_article_exist function need to be rewrite         
      if not models.UpdateItem.get_by_key_name(key_names = my_key_name, parent = pubsub_topic):
          #Use hashed key_name to save query time
          db.put(models.UpdateItem(parent = pubsub_topic, key_name=my_key_name))
          counter += 1                         
          logging.debug(entry)
          #logging.debug(content)          
          for gruser in grusers:
            if gruser.unsubscribe:
                continue
            else:
                logging.info(gruser.username)
                is_note = False
                pub = False
                #remove html element in content and title
                mycontent = re.sub("<[^>]*>","",content)
                title = re.sub("<[^>]*>","",title)
                if mycontent == title:              #it's a update only contains note
                    message = title.encode('utf-8') #encode the message for twitter
                    is_note = "Note"
                else:
                    if content.find("<blockquote")==0:
                        start = content.find("<br />\n")
                        end   = content.find("</blockquote>")
                        content = content[start+7:end]
                        content = re.sub("<[^>]*>","",content)
                        is_note = True              #it's a gr update that contains note
                    else:
                        content = ''
                    link = shorten(link,gruser.bitlylogin,gruser.bitlykey)
                    logging.debug("debug link")
                    logging.debug(link)
                    format = gruser.format          #get user's format
                    message = format_tweet(format,title,link,content,is_note)
                #message = message[:140]
                synctype = gruser.synctype
                #check if pub to twitter based on user's config 
                if synctype == "all" or not synctype:
                    logging.info("Sync All")
                    pub = True
                elif synctype == "note" and is_note == "Note":
                    logging.info("only Sync note")
                    pub = True
                elif synctype == "comment" and is_note:
                    logging.info("Sync gr with note")
                    pub = True
                else:
                    logging.info("Do not need to pub to twitter")
                if pub:
                    if counter > 2:
                        logging.info("超出2篇")
                        gruser.fetch_old()
                        break
                    else:
                        #if gruser.key().name(): 
                        #    if re.search("^Key_Weibo", gruser.key().name()):
                        #        sina_oauth_handler.update_weibo(gruser, message)        
                        if not gruser.oauth:
                            basestring = gruser.basestring
                            try:
                                logging.info(message)
                                pub_to_twitter_by_basestring(basestring,message)
                            except Exception,e:  
                                logging.debug("pub to twitter error:%s" % str(e))
                        else:
                            client = twitter_oauth_handler.OAuthClient('twitter', self)
                            client.token = get_token_by_username(gruser.username)
                            try:
                                logging.info(message)
                                client.post("/statuses/update",status = message)
                            except Exception,e:
                                logging.debug("pub to twitter error:%s" % str(e))
    logging.info("Published %d item(s) to Twitter" % counter)
    UpdateStat.update_today_stat("GoogleReader",counter)
    self.response.set_status(200)
    self.response.out.write("Aight.  Saved.")

def CutString(gs, length):
    gs = gs.encode("gb2312")
    us = unicode(gs, 'gbk')   
    n = int(length)*2   
    s_len = len(gs)
    if s_len < n:
        return gs
    t = gs[:n]
    while True:
        try:
            unicode(t, 'gbk')
            break
        except:
            n -= 1
            t = gs[:n] 
    return t.encode('utf-8')

def google_shorten(longUrl):
    try:
        request = urllib2.Request("https://www.googleapis.com/urlshortener/v1/url?key=AIzaSyC4RM0ZE6kAaUPLd0WZSYv-pH01PrnwWVo", data='{"longUrl": "%s"}' % longUrl, headers = {'Content-Type':'application/json'})
        response = urllib2.urlopen(request)
        content = response.read()
        return json.loads(content)['id']
    except:
        return ''
    

def shorten(link,login,apikey):
    try:
        if login and apikey:
            client=bitly.Api(login=login,apikey=apikey)
            short_link = client.shorten(link)
        else:
            short_link = google_shorten(link)
            if not short_link:
                short_link = urlfetch.fetch("http://is.gd/api.php?longurl=" + link).content
        return short_link
    except:
        return link
    
def format_tweet(format,title,link,comment,is_note):
    if not format:
        return title.encode("utf-8")+" "+link.encode("utf-8")+" "+comment.encode("utf-8")
    elif format.find("url")==-1:
        return title.encode("utf-8")+" "+link.encode("utf-8")+" "+comment.encode("utf-8")
    else:
        if format.find("{comment}")==-1:
            if not format.find("{title}")==-1:
                format = format.replace("{title}",title)
            format = format.replace("{url}",link)
            format = format.encode("utf-8")
        else:
            if comment == "":
                if not format.find("{title}")==-1:
                    a = format.find("{title}")
                    b = format.find("{url}")
                    if a>b:
                        format = format[:a+7] 
                    else:
                        format = format[:b+5]
            format = format.replace("{title}",title)
            format = format.replace("{url}",link)
            if is_note:
                format = format.replace("{comment}",comment)            
            else:
                format = format.replace("{comment}","")
            format = format.encode("utf-8")
        return format
            
class Test(webapp.RequestHandler):
    """Gets the items."""

    def get(self): 
      self.response.out.write(google_shorten("http://www.kangye.org"))

class TestOauthHandler(webapp.RequestHandler):
    """Demo Twitter App."""
 
    def get(self):
        HEADER = """
          <html><head><title>Twitter OAuth Demo</title>
          </head><body>
          <h1>Twitter OAuth Demo App</h1>
          """
         
        FOOTER = "</body></html>"
        
        client = twitter_oauth_handler.OAuthClient('twitter', self)
        #gdata = OAuthClient('google', self, scope='http://www.google.com/calendar/feeds')
 
        write = self.response.out.write; write(HEADER)
 
        if not client.get_cookie():
            write('<a href="/oauth/twitter/login">Login via Twitter</a>')
            write(FOOTER)
            return
        client.post("/statuses/update",status = "test from oauth")
        write('<a href="/oauth/twitter/logout">Logout from Twitter</a><br /><br />')
 
        info = client.get('/account/verify_credentials')
 
        write("<strong>Screen Name:</strong> %s<br />" % info['screen_name'])
        write("<strong>Location:</strong> %s<br />" % info['location'])
 
        rate_info = client.get('/account/rate_limit_status')
 
        write("<strong>API Rate Limit Status:</strong> %r" % rate_info)
 
        write(FOOTER)

class NewUser(webapp.RequestHandler):
    """Demo Twitter App."""
 
    def get(self):
        client = twitter_oauth_handler.OAuthClient('twitter', self)
        
        if not client.get_cookie():
            self.redirect('/')
            return
        
        info = client.get('/account/verify_credentials')
        
        if not info:
          self.response.out.write('Error occured when conmunicating with Twitter. Please <a href="/">try again</a>.')
        else:
          username = info['screen_name']
          gruser = is_user(username)
          language = get_language(self)
          if not gruser:
              gruser = GRUser(key_name='Key_Twitter_'+username,username = username, oauth = True)
              gruser.put()
              logging.debug("New Twitter-Login user.")
              logging.info(username)
          else:
              gruser.oauth = True
              gruser.put()
          if language == "cn":
              self.redirect('/cnuser')
          else:
              self.redirect('/enuser')

class FetchOld(webapp.RequestHandler):
    """fetch old items 
    todo: need to do some change to the key_name"""

    def get(self): 
        #logging.info("start fetching the rss of new user")
        update_list = []
        topic = self.request.get("topic")
        logging.info(topic)
        if topic.startswith("http"):
          gaehub = models.Hub.get_by_key_name("http://pubsubhubbub.appspot.com/subscribe")
          pubsub_topic = models.PubSubTopic.get_or_insert(key_name=topic, hub = gaehub, verify_token = str(uuid.uuid4()))
          entries = feedparser.parse(topic).entries
          for entry in entries:
              if hasattr(entry, 'content'):
                  # This is Atom.
                  entry_id = entry.id
              else:
                  entry_id = entry.get('id', '')
              if "buzz" in topic:
                my_key_name = 'key_' + hashlib.sha1(buzz_date(entry) + '\n' + topic).hexdigest()
              else:
                my_key_name = 'key_' + entry_id
              update_list.append(models.UpdateItem(parent = pubsub_topic, key_name=my_key_name))
          db.put(update_list)        
          self.response.set_status(200)
          self.response.out.write("Aight.  Saved.")   
    post = get
    
class SaveOld(webapp.RequestHandler):
    """Handles feed input and subscription"""
    def get(self):
        try:
            topic = self.request.get("topic")
            link   = self.request.get("link")
            old_update = SomeUpdate(topic=topic,link=link)
            old_update.put()        
        except:
            self.response.out.write("OK")
    post = get
    
class SubCN(webapp.RequestHandler):
    """fetch old items"""

    def get(self): 
        topics = Topic.all().fetch(500)
        for topic in topics:
            pub_queue = taskqueue.Queue("my-queue-1")
            task = taskqueue.Task(url='/subtopic',params=dict(topicurl=topic.url))
            pub_queue.add(task)            
        self.response.set_status(200)
        self.response.out.write("Aight.  Saved.")   
    post = get
    
class SyncCNOauth(webapp.RequestHandler):
  """Debug handler for simulating events."""
  def get(self):
    client = twitter_oauth_handler.OAuthClient('twitter', self)
    if not client.get_cookie():
        self.response.out.write('请<a href="/cn">登录</a>')   
        return
    try:
        info = client.get('/account/verify_credentials')
    except:
        self.redirect('/oauth/twitter/login')
        return
    gruser = is_user(info['screen_name'])
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
    self.response.out.write(template.render('syncoauth.html', template_value))
  def post(self):
    client = twitter_oauth_handler.OAuthClient('twitter', self)
    if client.get_cookie():
        client = twitter_oauth_handler.OAuthClient('twitter', self)
        info = client.get('/account/verify_credentials')
        username = info['screen_name']
        logging.info(username)
        #self.response.out.write("登录成功")
        grid = self.request.get("grid")
        if re.search(r"\d*",grid).group():
            topic = "http://www.google.com/reader/public/atom/user/%s/state/com.google/broadcast" % grid
            issync = self.request.get("mode")
            gruser = is_user(username)
            if issync == "subscribe":
                format = self.request.get("format")
                synctype = self.request.get("synctype")
                bitlylogin = self.request.get("bitlylogin")
                bitlykey = self.request.get("bitlykey")                
                logging.info(synctype)
                if gruser:
                    gruser.topic = topic
                    gruser.format = format
                    gruser.synctype = synctype
                    gruser.bitlykey = bitlykey
                    gruser.bitlylogin = bitlylogin
                    gruser.unsubscribe = False
                    gruser.put()
                else:
                    logging.info("新用户")
                    #basestring = base64.encodestring('%s:%s' % (username, password))[:-1]
                    gruser = GRUser(key_name='Key_Twitter_'+username,username = username,topic = topic, format = format)
                    gruser.put()
            elif gruser:
                logging.debug("用户退订")
                logging.debug(gruser.username)
                gruser.unsubscribe = True
                gruser.put()  
                return                
                #gruser.delete()            
            payload = {"hub.mode":issync,"hub.verify":"sync","hub.callback":"http://reader2twitter.appspot.com/subscriber","hub.topic":topic}
            payload= urllib.urlencode(payload)
            url = "http://pubsubhubbub.appspot.com/subscribe"
            try:
                result = urlfetch.fetch(url, payload=payload, method=urlfetch.POST)
                logging.info(result.status_code)
                if result.status_code == 204:  
                    logging.info("%s success" % issync)  
                    if issync == "unsubscribe":
                        self.response.out.write('You have stopped sync. Any suggestion to <a href="http://twitter.com/gr2t">gr2t</a>?')
                    else:
                        self.response.out.write("You sync is established. Wish you can share this tool in greader:) <a href=\"javascript:var%20b=document.body;var%20GR________bookmarklet_domain='http://www.google.com';if(b&&!document.xmlVersion){void(z=document.createElement('script'));void(z.src='http://www.google.com/reader/ui/link-bookmarklet.js');void(b.appendChild(z));}else{}\">click to share</a>")
                else:
                    logging.info("向hub订阅Publisher失败")
                    self.response.out.write('Please <a href="/buzz">retry</a>')
            except:
                logging.info("和hub连接失败")
                self.response.out.write('Please <a href="/buzz">retry</a>')
        else:
            logging.info("google reader id格式错误")
            self.response.out.write('Please use Google Profile <b>number</b> ID，<a href="/buzz">retry</a>')
    else:
        logging.info("没有oauth认证")
        self.response.out.write('Please <a href="/buzz">sign in</a>')

class SyncENOauth(webapp.RequestHandler):
  """Debug handler for simulating events."""
  def get(self):
    client = twitter_oauth_handler.OAuthClient('twitter', self)
    if not client.get_cookie():
        self.response.out.write('Please <a href="/en">sign in</a>')   
        return
    try:
        info = client.get('/account/verify_credentials')
    except:
        self.redirect('/oauth/twitter/login')
        return
    gruser = is_user(info['screen_name'])
    template_value = {}
    if gruser:
        mygruser = {}
        mygruser["username"]=gruser.username
        mygruser["format"]=gruser.format
        mygruser["bitlykey"]=gruser.bitlykey
        mygruser["bitlylogin"]=gruser.bitlylogin
        mygruser["synctype"]={}
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
    else:
        self.redirect("/")
    self.response.out.write(template.render('syncoauthen.html', template_value))
  def post(self):
    logging_now()
    client = twitter_oauth_handler.OAuthClient('twitter', self)
    if client.get_cookie():
        client = twitter_oauth_handler.OAuthClient('twitter', self)
        try:
            info = client.get('/account/verify_credentials')
        except DownloadError, e:
            self.response.out.write("Twitter connection error. Please retry:)")
        if not info:
            self.response.out.write('Twitter connection error. Please <a href="/">retry</a>:)')
        username = info['screen_name']
        logging.info(username)
        #self.response.out.write("登录成功")
        grid = self.request.get("grid")
        if re.search(r"\d*",grid).group():
            topic = "http://www.google.com/reader/public/atom/user/%s/state/com.google/broadcast" % grid
            logging.info(grid)
            issync = self.request.get("mode")
            gruser = is_user(username)
            if issync == "subscribe":
                format = self.request.get("format")
                synctype = self.request.get("synctype")
                bitlylogin = self.request.get("bitlylogin")
                bitlykey = self.request.get("bitlykey")                
                logging.info(synctype)
                if gruser:
                    gruser.topic = topic
                    gruser.format = format
                    gruser.synctype = synctype
                    gruser.bitlylogin = bitlylogin
                    gruser.bitlykey = bitlykey
                    gruser.unsubscribe = False
                    gruser.put()
                else:
                    logging.info("new user")
                    gruser = GRUser(key_name='Key_Twitter_'+username,username = username,topic = topic, format = format)
                    gruser.put()
            elif gruser:
                logging.info(issync)
                logging.debug("用户退订")
                logging.debug(gruser.username) 
                gruser.unsubscribe = True
                gruser.put()  
            payload = {"hub.mode":issync,"hub.verify":"sync","hub.callback":"http://reader2twitter.appspot.com/subscriber","hub.topic":topic}
            payload= urllib.urlencode(payload)
            url = "http://pubsubhubbub.appspot.com/subscribe"
            try:
                result = urlfetch.fetch(url, payload=payload, method=urlfetch.POST)
                if result.status_code == 204:
                    fetch_queue = taskqueue.Queue("fetch-old")
                    task = taskqueue.Task(url='/fetchold',params=dict(topic=topic))
                    fetch_queue.add(task)  
                    logging.info("%s success" % issync)              
                    if issync == "unsubscribe":
                        self.response.out.write('You have stopped sync. Any suggestion to <a href="http://twitter.com/gr2t">gr2t</a>?')
                    else:
                        self.response.out.write("You sync is established. Wish you can share this tool in greader:) <a href=\"javascript:var%20b=document.body;var%20GR________bookmarklet_domain='http://www.google.com';if(b&&!document.xmlVersion){void(z=document.createElement('script'));void(z.src='http://www.google.com/reader/ui/link-bookmarklet.js');void(b.appendChild(z));}else{}\">click to share</a>")
                        
                else:
                    logging.info("向hub订阅Publisher失败")
                    self.response.out.write('Please <a href="/enuser">retry</a>')
            except:
                logging.info("和hub连接失败")
                self.response.out.write('Please <a href="/enuser">retry</a>')
        else:
            logging.info("google reader id格式错误")
            self.response.out.write('Please use Google Reader <b>number</b> ID，<a href="/enuser">retry</a>')
    else:
        logging.info("没有oauth认证")
        self.response.out.write('Please <a href="/en">sign in</a>')

class BuzzENOauth(webapp.RequestHandler):
  """Debug handler for simulating events."""
  def get(self):
    try:
        client = twitter_oauth_handler.OAuthClient('twitter', self)
        if not client.get_cookie():
            self.response.out.write(template.render('buzzen.html',''))  
            return
        try:
            info = client.get('/account/verify_credentials')
        except:
            self.redirect('/oauth/twitter/login')
            return
    except:
        self.response.out.write('Reader2Twitter has a problem with Twitter API. <a href="/buzz">Retry</a>')
        return
    gruser = is_user(info['screen_name'])
    template_value = {}
    if gruser:
        mygruser = {}
        mygruser["username"]=gruser.username
        mygruser["bitlykey"]=gruser.bitlykey
        mygruser["bitlylogin"]=gruser.bitlylogin
        if gruser.buzztopic:
            #mygruser["profileid"] = gruser.buzztopic.replace("http://buzz.googleapis.com/feeds/","")
            mygruser["profileid"] = gruser.buzztopic.replace("https://www.googleapis.com/buzz/v1/activities/", '')
            mygruser["profileid"] = mygruser["profileid"].replace("http://www.googleapis.com/buzz/v1/activities/", '')
            #mygruser["profileid"] = mygruser["profileid"].replace("/public/posted","")
            mygruser["profileid"] = mygruser["profileid"].replace("/@public", '')
        template_value = {"gruser":mygruser} 
    else:
        self.redirect("/oauth/twitter/login")
    self.response.out.write(template.render('buzzoauthen.html', template_value))
  def post(self):
    logging_now()
    client = twitter_oauth_handler.OAuthClient('twitter', self)
    if client.get_cookie():
        client = twitter_oauth_handler.OAuthClient('twitter', self)
        info = client.get('/account/verify_credentials')
        username = info['screen_name']
        logging.info(username)
        gpid = self.request.get("gpid")
        if re.search(r"\d*",gpid).group():
            #buzztopic = "http://buzz.googleapis.com/feeds/%s/public/posted" % gpid
            buzztopic = "https://www.googleapis.com/buzz/v1/activities/%s/@public" % gpid
            #topic = "http://www.google.com/reader/public/atom/user/%s/state/com.google/broadcast" % grid
            logging.info(gpid)
            issync = self.request.get("mode")
            buzzlink = self.request.get("buzzlink")
            gruser = is_user(username)
            if issync == "subscribe":
                if gruser:
                    gruser.buzztopic = buzztopic
                    gruser.buzzlink = buzzlink
                    gruser.put()
                else:
                    logging.info("new user")
                    gruser = GRUser(key_name='Key_Twitter_'+username,username = username,buzztopic = buzztopic)
                    gruser.buzzlink = buzzlink
                    gruser.put()
            elif gruser:
                logging.info(issync)
                logging.debug("用户退订")
                logging.debug(gruser.username) 
                #gruser.put()  
                #return                                           
            payload = {"hub.mode":issync,"hub.verify":"sync","hub.callback":"http://reader2twitter.appspot.com/buzzpush","hub.topic":buzztopic}
            payload= urllib.urlencode(payload)
            url = "http://pubsubhubbub.appspot.com/subscribe"
            try:
                result = urlfetch.fetch(url, payload=payload, method=urlfetch.POST)
                logging.info(result.status_code)
                if result.status_code == 204 or result2.status_code == 204:  
                    logging.info("%s success" % issync)  
                    if issync == "unsubscribe":
                        self.response.out.write('You have stopped sync. Any suggestion to <a href="http://twitter.com/gr2t">gr2t</a>?')
                    else:
                        self.response.out.write("You sync is established. Wish you can share this tool in greader:) <a href=\"javascript:var%20b=document.body;var%20GR________bookmarklet_domain='http://www.google.com';if(b&&!document.xmlVersion){void(z=document.createElement('script'));void(z.src='http://www.google.com/reader/ui/link-bookmarklet.js');void(b.appendChild(z));}else{}\">click to share</a>")
                else:
                    logging.info("向hub订阅Publisher失败")
                    self.response.out.write('Please <a href="/buzz">retry</a>')
            except:
                logging.info("和hub连接失败")
                self.response.out.write('Please <a href="/buzz">retry</a>')
        else:
            logging.info("google reader id格式错误")
            self.response.out.write('Please use Google Profile <b>number</b> ID，<a href="/buzz">retry</a>')
    else:
        logging.info("没有oauth认证")
        self.response.out.write('Please <a href="/buzz">sign in</a>')

class SyncEN(webapp.RequestHandler):
  """Debug handler for simulating events."""
  def get(self):
    logging.info('test')
    client = twitter_oauth_handler.OAuthClient('twitter', self)
    if client.get_cookie():    
        self.redirect("/enuser")
        return    
    set_language(self,"en")
    self.response.out.write(template.render('syncen.html', {}))

def pub_to_twitter_by_basestring(basestring,message):
    payload= {'status' : message}
    payload= urllib.urlencode(payload)
    
    headers = {'Authorization': "Basic %s" % basestring}
    
    url = "http://twitter.com/statuses/update.xml"
    result = urlfetch.fetch(url, payload=payload, method=urlfetch.POST, headers=headers)
    
def login_to_twitter(login,password):
    login = login
    password = password
    
    base64string = base64.encodestring('%s:%s' % (login, password))[:-1]
    headers = {'Authorization': "Basic %s" % base64string}
    
    url = "http://twitter.com/account/verify_credentials.xml"
    result = urlfetch.fetch(url, method=urlfetch.GET, headers=headers)
    if not result.content.find("Could not authenticate you.")==-1:
        return False
    else:
        logging.info("twitter user %s is using r2t" % login)
        return True

def is_article_exist(my_key_name,topic,link):
    if SomeUpdate.get_by_key_name(my_key_name):
        logging.debug("article exists detected by key_name")
        return True
    else:
        try:
            query = SomeUpdate.all(keys_only=True).filter("link = ",link).filter("topic = ",topic)
            if query.count()==0:
                return False
            else:
                transfer_item_to_key(query,my_key_name)
                return True
        except Exception,e:
            logging.error(str(e))
            return True

def transfer_item_to_key(query,my_key_name):
    SomeUpdate.get_or_insert(key_name=my_key_name)
    db.delete(query)
    logging.info("transfer item to key_name: done")

def is_user(username):
    query = GRUser.all().filter("username = ",username)
    if query.count()==0:
        return None
    else:
        for gruser in query:
            return gruser
            break 
        
def get_user_by_topic(topic):
    """return the user who subscribe the topic
    parameter:topic"""
    query = GRUser.all().filter("topic = ",topic)
    if query.count() == 0:
        return False
    else:
        return query  

def get_user_by_buzztopic(topic):
    """return the user who subscribe the topic
    parameter:topic"""
    if '?' in topic:
      topic = topic[:topic.find('?')]
    query = GRUser.all().filter("bt = ",topic)
    if query.count() == 0:
        return False
    else:
        return query  

def get_token_by_username(username):
    query = twitter_oauth_handler.OAuthAccessToken.all().filter("specifier = ",username)
    for token in query:
        return token
    
def get_language(handler):
    return handler.request.cookies.get('reader2twitter.language')

def set_language(handler, language, path='/'):
    handler.response.headers.add_header(
        'Set-Cookie', 
        '%s=%s; path=%s; expires="Fri, 31-Dec-2021 23:59:59 GMT"' %
        ('reader2twitter.language' , language, path)
        )

class NotPage(webapp.RequestHandler):
    """Debug handler for simulating events."""
    def get(self,url=''):
			self.response.set_status(200)
			self.response.out.write("Under Maintenance:) Be back soon!")
    post = get

class SocialGraph(webapp.RequestHandler):
    """Debug handler for simulating events."""
    def get(self):
      email = self.request.get("openid.ext1.value.email")
      if not email:
        self.response.out.write('<a href="https://www.google.com/accounts/o8/ud?openid.ns=http://specs.openid.net/auth/2.0&openid.ns.pape=http://specs.openid.net/extensions/pape/1.0&openid.ns.max_auth_age=300&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://reader2twitter.appspot.com/socialgraph&openid.realm=http://reader2twitter.appspot.com/&openid.assoc_handle=ABSmpf6DNMw&openid.mode=checkid_setup&openid.ui.ns=http://specs.openid.net/extensions/ui/1.0&openid.ui.mode=popup&openid.ui.icon=true&openid.ns.ax=http://openid.net/srv/ax/1.0&openid.ax.mode=fetch_request&openid.ax.type.email=http://axschema.org/contact/email&openid.ax.type.language=http://axschema.org/pref/language&openid.ax.required=email">login with Google Account</a>')
      else:
        self.response.out.write(get_google_reader_uri(email))

def get_google_reader_uri(email):
  social_graph_uri = "http://socialgraph.apis.google.com/otherme?q=%s&pretty=true" % email
  social_graph = json.loads(urllib.urlopen(social_graph_uri).read())
  google_reader_url = ""
  for key in social_graph.keys():
    if key.startswith("http://www.google.com/reader/shared/"):
      google_reader_url = key
      break
  return google_reader_url


application = webapp.WSGIApplication(
  [
    (r'/test', Test),
    (r'/fetchold',FetchOld),
    (r'/subscriber.*', InputHandler),
    (r'/buzzpush.*', BuzzPuSH),
    (r'/', SyncEN),
    (r'/en', SyncEN),
    (r'/feedr',Feedr),
    (r'/pubtwitter',PubTwitter),
    (r"/updatestat",UpdateStat),
    (r"/saveold",SaveOld),
    (r"/newuser",NewUser),
    (r"/enuser",SyncENOauth),
    (r'/cn', SyncENOauth),
    (r'/buzz',BuzzENOauth),
    (r'/socialgraph', SocialGraph),
    (r'/(.*)',NotPage)
  ],
  debug=True)

def main():
  wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
  main()
