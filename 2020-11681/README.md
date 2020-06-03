An Information Disclosure, CVE-2020-11681, was identified on **Castel NextGen DVR** version 1.0.0 due to credentials being disclosed in Cleartext and visible in the source of the page.

## Timeline

* Issue Disclosed: 3 Jun 2020 - [Blog post](https://www.securitymetrics.com/blog/attackers-known-unknown-authorization-bypass)

## Description

Users with the Administrator role can view credentials for Accounts,
like the associated SMTP server, by viewing the source of the
**/Administrationr/SMTP** server:

![](source.png)

A malicious user that compromises an account or leverages the reported
[CSRF](../CVE-2020-11680/README.md) to create an account would be able
to gain access to the SMTP server credentials.
