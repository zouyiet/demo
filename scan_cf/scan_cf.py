#!/usr/bin/env python
# encoding: utf-8

from gevent import monkey

monkey.patch_all()
from gevent.pool import Pool
import requests, time
from bs4 import BeautifulSoup


class scan_cf:
    def __init__(self, user, passwd):
        self.login_url = "http://x/login.action"
        self.user = user
        self.passwd = passwd
        self.keyword = ["密码", "帐号", "password"]
        self.login_payload = {"os_username": self.user, "os_password": self.passwd}
        self.filename = time.strftime('%Y-%m-%d_%H_%M_%S', time.localtime(time.time()))
        self.file = open(self.filename + ".txt", "a+")

    def login_get_cookies(self):
        try:
            req = requests.post(url=self.login_url, data=self.login_payload, allow_redirects=True, timeout=10)
            if req.ok:
                cookies = dict(JSESSIONID=req.cookies['JSESSIONID'])
                return cookies
        except Exception, e:
            print 'LOGIN ERR', e

    def scan_keyword(self):
        while True:
            for keyword in self.keyword:
                for count in xrange(0, 110, 10):
                    scan_url = "http://x/dosearchsite.action?queryString=%s&where=conf_all&startIndex=%s" % (
                    keyword, str(count))
                    req = requests.get(url=scan_url, cookies=self.login_get_cookies(), allow_redirects=True)
                    if req.ok:
                        print scan_url
                        soup = BeautifulSoup(req.content, 'lxml')
                        if '找不到针对' in str(soup):
                            break
                        for data in soup.find_all('li'):
                            if "<li><h3><span" in str(data):
                                for item in self.keyword:
                                    if item in str(data):
                                        data = str(data).replace('</strong>', '').replace('<strong>', '').split("…")[0]
                                        self.operate_file(data)
            break

    def operate_file(self, data):
        self.file.write(data + '\r\n')


if __name__ == '__main__':
    stime = time.time()
    erp_user, erp_passwd = "erp", "password"
    t = scan_cf(erp_user, erp_passwd)
    t.scan_keyword()
    t.file.close()
    print "Cost  : %.2f's" % (time.time() - stime)
