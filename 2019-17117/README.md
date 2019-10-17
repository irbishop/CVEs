A SQL Injection vulnerability, CVE-2019-17117, was identified on `WiKID Systems 2FA Enterprise Server` through version `4.2.0-b2053`.  The <var>key</var> parameter, used in **processPref.jsp**, is not sanitized thus allowing an authenticated user to create, read, update, or delete arbitrary information in the database.  

## Patch

* **4.2.0.b2053**: <https://downloads.wikidsystems.com/wikid-server-enterprise-4.2.0.b2053-1.noarch.rpm>

## Timeline

* 26 Sep 2019 - Issue discovered on `WiKID Systems 2FA Enterprise Server 4.2.0-b2032`
* 29 Sep 2019 - Issue disclosed to WiKID Systems
* 09 Oct 2019 - Issue confirmed by WiKID Systems, Patch released
* 16 Oct 2019 - Public Disclosure

## Description

Reviewing the source code for **processPref.jsp** revealed the following code block:

~~~
121     } else if (request.getParameter("action").equals("Update")) {
122         // need to do error checking here.
123         sql = "SELECT key FROM parms1to1 where key='" + request.getParameter("key") + "'";
124         ResultSet result = stat.executeQuery(sql);
125         if (!result.next()) {
126     %>
~~~

If the <var>action</var> parameter is set to `Update`, the <var>key</var> parameter is included in a SQL query used to retrieve the Parameter that will be updated.  The <var>key</var> parameter is not sanitized when it is included in the query so a request such as:

~~~
https://$RHOST/WiKIDAdmin/processPref.jsp?action=Update&key=test%27;%20SELECT%20pg_sleep(5);--
~~~ 

Will cause the application to delay for at least 5 seconds.
