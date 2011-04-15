from google.appengine.ext import db
from google.appengine.api.labs import taskqueue
from google.appengine.ext.db import polymodel
import time
import logging
import re
#import bulkupdate

class GRUser(db.Model):
  """Google Rreader User with twitter account"""
  username = db.StringProperty()
  basestring = db.StringProperty(indexed=False)
  bitlylogin = db.StringProperty(default = "",indexed=False)
  bitlykey = db.StringProperty(default = "",indexed=False)
  joined = db.DateTimeProperty(auto_now_add=True)
  topic = db.StringProperty()
  buzztopic = db.StringProperty(name="bt")
  buzzlink = db.StringProperty(name="blk",indexed=False)
  format = db.StringProperty(default = "",indexed=False)
  synctype = db.StringProperty(default = "all",indexed=False)
  oauth  = db.BooleanProperty(default = False,indexed=False)
  unsubscribe = db.BooleanProperty(default = False,indexed=False)

  @staticmethod
  def clear_all_old_updates():
    gr_q = db.GqlQuery("SELECT * FROM GRUser")
    gr_cur = ''
    count = gr_q.count()
    while count >0:
      grusers = gr_q.fetch(200)
      gr_cur = gr_q.cursor()
      gr_q.with_cursor(gr_cur)
      for gruser in grusers:
        gruser.delete_old_updates()
      count = gr_q.count()

  @staticmethod
  def fetch_all_old():
    job = bulkupdate.BulkDeleteOld(GRUser.all())
    job.start()

  def fetch_old(self):
    logging.info("fetch old buzz for %s" % self.username)
    fetch_queue = taskqueue.Queue("fetch-old")
    task = taskqueue.Task(url='/fetchold',params=dict(topic=self.topic)) #self.buzztopic
    fetch_queue.add(task)

  def fetch_old_default(self):
    logging.info("fetch old buzz for %s" % self.username)
    #task = taskqueue.Task(url='/fetchold',params=dict(topic=self.topic)) #self.buzztopic
    taskqueue.add(url = '/fetchold', params = dict(topic = self.topic))

  def fetch_old_buzz_default(self):
    logging.info("fetch old buzz for %s" % self.username)
    #task = taskqueue.Task(url='/fetchold',params=dict(topic=self.topic)) #self.buzztopic
    taskqueue.add(url = '/fetchold', params = dict(topic = self.buzztopic))

  def backup_updates(self):
    username = self.username
    topic = self.topic
    if topic:
      q = db.GqlQuery("SELECT * FROM SomeUpdate WHERE topic = :1 ORDER BY updated", topic)
      cur = ''
      if q.count()>0:
        f = open('/Users/mac/Dropbox/GAE/reader2twitter/backup/%s.csv' % username, 'w')
        while q.count()>0:
          updates = q.fetch(1000)
          cur = q.cursor()
          q.with_cursor(cur)
          for update in updates:
            updated = update.updated.strftime("%Y.%m.%d %H:%M:%S")
            f.write('"%s","%s"\n' % (update.link, update.updated))
        f.close()
        return 1
      else:
        return 0
    else:
      return 0

  def delete_old_updates(self):
    topic = self.topic
    if topic:
      q = db.GqlQuery("SELECT * FROM SomeUpdate WHERE topic = :1 ORDER BY updated DESC", topic)
      count = q.count()
      if count > 50:
        new_updates = q.fetch(50)
        cur = q.cursor()
        q.with_cursor(cur)
        count = q.count()
        if count > 0:
          print count
          db.delete(q.fetch(100))
          time.sleep(100)
          #print "sleep 100s"


class SomeUpdate(db.Model):
  """Some topic update.

  Key name will be a hash of the feed source and item ID.
  """
  topic = db.StringProperty()
  updated = db.DateTimeProperty(auto_now_add=True)
  link = db.StringProperty()

  @staticmethod
  def clear_updates():
    logging.info("start to clear updates")
    db.delete(SomeUpdate.all(keys_only=True).fetch(100))

#class Topic(db.Model):
#  url = db.StringProperty()
#  subscribe = db.BooleanProperty(default = False)
#
#  @staticmethod
#  def clear_all_topic():
#    job = bulkupdate.BulkDelete(Topic.all(keys_only=True))
#    job.start()


class UpdateItem(db.Model):
  """achieve every update item with an uinque key_name

  Key name will be a hash of the feed source and link.
  parent: PubSubTopic
  """

  updated = db.DateTimeProperty(auto_now_add=True)


class Hub(db.Model):
  """An abstract model for hub
  key_name: the hub url"""

  description = db.StringProperty()
  @property
  def url(self):
    return self.key().name()


class Service(db.Model):
  """An abstract model for service
  parent: Topic
  """

  user = db.ReferenceProperty(GRUser)
  stype = db.StringProperty()
  

class Topic(polymodel.PolyModel):
  """An abstract model for topic
  
  property:name
  Topic names are limited to 256 characters.

  key_name: an unique indicator of this topic
  """

  description = db.StringProperty()

class PubSubTopic(Topic):
  """key_name: the topic feedurl"""
  @property
  def feedurl(self):
    return self.key().name()
  
  hub = db.ReferenceProperty(Hub)  # hub for this pubsub topic
  verify_token = db.StringProperty()  # Random verification token.
  
  def is_old_buzz(self):
    if "buzz.googleapis.com" in self.feedurl:
      return True
    else:
      return Falsa

  def is_greader(self):
    if "com.google/broadcast" in self.feedurl:
      return True
    else:
      return False

  def get_buzzid_from_old_buzztopic(self):
    if re.findall("[0-9]+", self.feedurl):
      return re.findall("[0-9]+", self.feedurl)[0]

  def subscribe(self):
    subscribe_args = {
        'hub.callback': urlparse.urljoin(self.request.url, '/hubbub'), #maybe need to change
        'hub.mode': 'subscribe',
        'hub.topic': self.feedurl,
        'hub.verify': 'async',
        'hub.verify_token': self.verify_token,
    }

    headers = {}

    if HUB_CREDENTIALS:
      auth_string = "Basic " + base64.b64encode("%s:%s" % HUB_CREDENTIALS)
      headers['Authorization'] = auth_string

    response = urlfetch.fetch(self.hub.url, payload=urllib.urlencode(subscribe_args),
                              method=urlfetch.POST, headers=headers)
    if response.status_code == 204:
      return 1
      

class AmazonTopic(Topic):
  """key_name: the Amazon Resource Name of this topic
  """
  def create(self):
    return 1
    

