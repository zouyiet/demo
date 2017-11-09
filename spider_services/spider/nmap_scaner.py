#!/usr/bin/ python
# -*- coding: utf-8 -*-

from gevent import monkey
monkey.patch_all()
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from gevent.pool import Pool
import hashlib,MySQLdb,time
#import  whatweb_scanner


ip_file = open("baiduip250.txt","r")
ip_list = [ip.replace("\n","") for ip in ip_file.readlines()]

def do_scan(targets):
    parsed = None
    nmproc = NmapProcess(targets, "-sV -open -T5 -PE")
    rc = nmproc.run()
    if rc != 0:
        pass
    try:
	#20170504 modify /lib/libnmap/parse 84 --> nmap_data = str(nmap_data) bcz nmap_data linux create xml is unicode ,cant be work
	parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        #print("Exception raised while parsing scan: {0}".format(e.msg))
	print "nmap error",e

    if parsed:
        for host in parsed.hosts:
            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            else:
                tmp_host = host.address
            for serv in host.services:
                #print tmp_host , host.address, str(serv.port), serv.protocol, serv.state, serv.service
		to_mysql(tmp_host , host.address, str(serv.port), serv.protocol, serv.service)	


def to_mysql(domain, ip, port, protocol, service):
    domain, ip, port, protocol, service = domain, ip, port, protocol, service
    hash_data = hashlib.md5(ip+port+service+protocol)
    hash_data.update(ip+port+service)
    hash_content = hash_data.hexdigest()
    try:
        cur.execute("insert into baidu_portmap (hash,domain,ip,port,protocol,service) values ('%s','%s','%s','%s','%s','%s')"%(hash_content,domain,ip,port,protocol,service))
        conn.commit()
    except MySQLdb.Error,e:
        print "mysql error",e


def run():
    pool = Pool(50)
    pool.map(do_scan,ip_list)

if __name__=="__main__":
    conn = MySQLdb.connect(host="localhost",user="root",passwd="root",db="spider")
    cur = conn.cursor()
    cur.execute('SET NAMES UTF8')
    cur.execute('truncate baidu_portmap')
    cur.execute('truncate baidu_banner')
    conn.commit()
    run()
#    whatweb_scanner.banner_run()
    cur.close()
    conn.close()

