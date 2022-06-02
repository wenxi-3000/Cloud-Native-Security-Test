FROM debian:buster

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
    && sed -i 's|security.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' /etc/apt/sources.list

RUN apt update -y \
    && apt --fix-broken install \
    && apt update -y \
    && apt install -y \
    vim \
    curl \
    zsh \
    netcat \
    telnet \
    python \
    perl \
    php \
    ruby \
    busybox \
    gcc \
    golang \
    inotify-tools \
    kmod \
    openssh-server \
    unzip \
    tar \
    libcap2-bin    

ADD apache-tomcat-8.5.31.tar.gz /usr/local
ADD jdk-8u251-linux-x64.tar.gz /usr/local

RUN mkdir /root/.ssh \
    && touch /root/.ssh/authorized_keys

COPY java-sec-code-1.0.0.jar  /root
COPY inject.jar /root
COPY inject.jar /root
COPY msfshell.elf /root
COPY shell-agent.jar /root
COPY jsp /usr/local/apache-tomcat-8.5.31/webapp/ROOT
COPY id_rsa.pub /root/
COPY cdk_linux_amd64 /root
COPY fscan_amd64 /root
COPY script /root

RUN cat /root/id_rsa.pub >> /root/.ssh/authorized_keys

#环境变量
ENV JAVA_HOME /usr/local/jdk1.8.0_251
ENV CLASSPATH $JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar 
ENV CATALINE_BASE /usr/local/apache-tomcat-8.5.31
ENV PATH $PATH:$JAVA_HOME/bin:$CATALINA_HOME/lib:$CATALINA_HOME/bin 

#启动测试脚本
COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/apache-tomcat-8.5.31/bin/catalina.sh", "run"]