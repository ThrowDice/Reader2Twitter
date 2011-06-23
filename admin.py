from google.appengine.ext.webapp import template 
from django.utils import simplejson
import logging
import datetime

from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import deferred
from google.appengine.api import mail

import pubsub
from pubsub import UpdateStat
from models import SomeUpdate
from models import GRUser
from twitter_oauth_handler import OAuthClient
from mapreduce import control

class MainPage(webapp.RequestHandler):
    def get(self):
        template_value = {}
        self.response.out.write(template.render('admin.html', template_value))

class RUSGraph(webapp.RequestHandler):
    """show Recent UpdateStat Graph"""

    def get(self):
        graph_url = UpdateStat.recent_stats_graph_url()
        logging.info(graph_url)
        self.response.out.write('<img src="%s"/>' % graph_url)

class DeleteOldUpdates(webapp.RequestHandler):
    def get(self):
        mapreduce_params = {
              'entity_kind': 'models.Topic',
        }
        
        control.start_map("DeleteOldUpdates", "mapjob.keep_thirty_updates", "mapreduce.input_readers.DatastoreInputReader", mapreduce_params, 2)
        self.response.out.write("ok")

class MailUpdateStat(webapp.RequestHandler):
    """Send a daily stat summary email to admin"""

    def get(self):
        today = str(datetime.date.today()+datetime.timedelta(days=-1))
        tdgrkeyname = "GoogleReader%s" % (today)
        tdgbkeyname = "GoogleBuzz%s" % (today)        
        today_gr_stat = UpdateStat.get_or_insert(tdgrkeyname)
        today_gb_stat = UpdateStat.get_or_insert(tdgbkeyname) 
        today_all = today_gr_stat.counter+today_gb_stat.counter
        sender_address = "G2T <areyoulookon@gmail.com>"
        subject = "[%s]G2T Daily UpdateStat Summary" % today
        body = """

Daily Google Reader Update : %d
Daily Google Buzz Update   : %d
Daily All Update   : %d


""" % (today_gr_stat.counter,today_gb_stat.counter,today_all)
        mail.send_mail_to_admins(sender_address, subject, body)


application = webapp.WSGIApplication(
                                     [(r'/admin/', MainPage),
                                      (r'/admin/db/cou', DeleteOldUpdates),
                                      (r'/admin/stat/rusgraph',RUSGraph),
                                      (r'/admin/mail/updatesummary',MailUpdateStat)],
                                     debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

