   只适合轻量的扫内网，因为端口是固定的，理论上应该从API接口同步过来生成list再用多线程扫描
   增加了js写的扫描redis并反弹shell的js
   默认只扫Centos主机（/var/spool/cron），只扫主机所在的C段（255个主机），需要自己改反弹shell到的IP