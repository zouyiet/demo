
#!/usr/bin/ python
# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding("UTF-8")

from gevent import monkey
from gevent.pool import Pool
monkey.patch_all()
import subprocess
import traceback
import hashlib,MySQLdb,time
import requests
from bs4 import BeautifulSoup

ip_list = []

conn= MySQLdb.connect(host='localhost',port = 3306,user='root',passwd='root',db ='spider')
cur = conn.cursor()
cur.execute('SET NAMES UTF8')

def create_list():
        cur.execute("select ip,port from baidu_portmap where service like '%http%'")
        get_all = cur.fetchall()
        print len(get_all)
        for data in get_all:
            if data[1] == "443":
                ip_list.append("https://"+data[0])
            else:
                ip_list.append("http://"+data[0]+":"+data[1])

def whatweb_scan(targets):
        try:
                cmd = "whatweb "+targets
                obj = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
                obj.wait()
                lines = obj.stdout.readlines()
                if not lines or len(lines) == 0:
                        line = obj.stderr.readlines()
                #print lines
                data = lines[-1].decode().encode()
                #print targets,data
                data_all = data.split(",")
                for item in data_all:
                        domain = data_all[0]
                        if "Country" in item:
                                country = item.strip()
                        elif "HTTPServer" in item:
                                server = item
                        elif "IP" in item:
                                ip = item
                        elif "Title" in item:
                                title = item
                try:
                        hash_data = hashlib.md5(ip+title)
                        hash_data.update(ip+title)
                        hash_content = hash_data.hexdigest()
                        #print "whatweb -->",domain+" "+ip+" "+title
                        cur.execute("insert into baidu_banner (domain,ip,title,country,server,hash_content) values ('%s','%s','%s','%s','%s','%s')"%(domain ,ip ,title ,country ,server,hash_content))
                        conn.commit()
                except MySQLdb.Error,e:
                        print e
        except Exception, e:
                check(targets)

def check(targets):
    try:
        req = requests.get(targets,timeout=2,allow_redirects=True)
        res = req.content
        if req.ok:
            soup = BeautifulSoup(res,"lxml")
            spt = soup.title
            #print "check -->",spt
            body = soup.body
            sptdecode = spt.text
            sptencode = sptdecode.encode("utf-8")
            #print "targets--->: ",target+" "+spt
            try:
                hash_data = hashlib.md5(targets+spt)
                hash_data.update(targets+spt)
                hash_content = hash_data.hexdigest()
                cur.execute("insert into baidu_banner (domain,title,hash_content) values ('%s','%s','%s')"%(targets,spt,hash_content))
                conn.commit()
            except MySQLdb.Error,e:
                print e
    except Exception as e:
         pass

def banner_run():
        create_list()
        pool = Pool(10)
        pool.map(check,ip_list)
        cur.close()
        conn.close()
                                                                                     