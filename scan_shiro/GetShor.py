# coding=utf-8

import sys
reload(sys)
sys.setdefaultencoding('utf8')

from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
import requests

keyword = "rememberMe=deleteMe"
domain_pool = []

def Create_Domain():
    with open ("dianrong.txt","r") as f:
        for data in f.readlines():
            data = data.strip()
            domain_pool.append(data)

def GetShiro(url):
    Cookies = {'rememberMe':'asdf'}
    try:
        req = requests.get(url=url, cookies =Cookies )
        res = req.headers
        if req.ok:
            for data in res.values():
                if keyword in data:
                    print "found -->",url,res
    except:
        pass


pool = Pool(100)
Create_Domain()
pool.map(GetShiro,domain_pool)

