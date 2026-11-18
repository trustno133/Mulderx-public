# SSTI -- Top 28 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980) -- Uber | $10,000 | Code Injection | 137up
  > Hi, Uber Security Team  I found an RCE in rider.uber.com. First, if you change your profile name to {{ '7'*7 }}, and you will receive a mail "Your Uber account information has been updated" sent by support@uber.com  And in mail body, you can see your name become '7777777'  This is a vulnerability about Flask Template Engine(Jinja2) Injection , more detail can be seen in these...
- [Reflected XSS on developer.uber.com via Angular template injection](https://hackerone.com/reports/125027) -- Uber | $3,000 | Cross-site Scripting (XSS) - Generic | 35up
  > developer.uber.com is vulnerable to reflected XSS via Angular template injection.  The following url demonstrates the root issue using a trivial payload: https://developer.uber.com/docs/deep-linking?q=wrtz{{7*7}}  If you view the rendered source of the resulting page, you'll find the string 'wrtz49', showing the input has been evaluated.  This URL uses an Angular sandbox escape to obtain...
- [[Ruby]: Server Side Template Injection](https://hackerone.com/reports/1928279) -- GitHub Security Lab | $2,300 | 13up
- [Path traversal, SSTI and RCE on a MailRu acquisition](https://hackerone.com/reports/536130) -- Mail.ru | $2,000 | Code Injection | 152up
- [XSS in $shop$.myshopify.com/admin/ via twine template injection in "Shopify.API.Modal.input" method when using a malicious app](https://hackerone.com/reports/217790) -- Shopify | $1,000 | Cross-site Scripting (XSS) - Generic | 31up
  > This report demonstrated an XSS that could be exploited by a malicious application installed on a store to execute javascript as a store administrator. The cause of the XSS turned out to be improperly escaped user input in a lodash template.
- [Unauthenticated SSRF in 3rd party module "cerdic/csstidy"](https://hackerone.com/reports/1595006) -- Nextcloud | $250 | Server-Side Request Forgery (SSRF) | 17up
  > Advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-24pm-rjfv-23mh
- [H1514 Server Side Template Injection in Return Magic email templates?](https://hackerone.com/reports/423541) -- Shopify | Code Injection | 409up
  > Full story with explanation of how this was exploited can be found here: https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html
- [Urgent: Server side template injection via Smarty template allows for RCE](https://hackerone.com/reports/164224) -- Unikrn | Code Injection | 122up
  > Hi All, I've found an issue which has allowed me to execute file_get_contents and extract your /etc/passwd file.  ##Description It appears as though you are using smarty on the backend for templating. Entering a malicious payload as my firstname, lastname and nickname and then inviting a user to join the site results in the code being executed.  To start, I began with the payload {7*7} and...
- [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection and audit-forward](https://hackerone.com/reports/2332623) -- GitHub | Command Injection - Generic | 80up
  > A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring audit log forwarding. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor...
- [Reflected XSS and Server Side Template Injection  in all HubSpot CMSes](https://hackerone.com/reports/399462) -- HubSpot Inactive | 64up
- [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection](https://hackerone.com/reports/2332551) -- GitHub | Command Injection - Generic | 61up
  > A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring SMTP options. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This...
- [Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com](https://hackerone.com/reports/301406) -- Ubiquiti Inc. | 47up
  > The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak.  This vulnerability don't have any impact and don't offer any threat...
- [Client Side Template Injection to Stored XSS in Image Collection](https://hackerone.com/reports/2234564) -- Mars | Cross-site Scripting (XSS) - Stored | 39up
  > Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages. When rendering a page, the framework scans it for template expressions and executes any that it encounters. An attacker can exploit this by supplying a malicious template expression that launches a cross-site scripting (XSS) attack. Attacker...
- [Python : Add query to detect Server Side Template Injection](https://hackerone.com/reports/944359) -- GitHub Security Lab | 29up
- [[mercantile.wordpress.org] Reflected XSS via AngularJS Template Injection](https://hackerone.com/reports/230234) -- WordPress | Cross-site Scripting (XSS) - Reflected | 29up
  > In a follow-up to resolved report #221893, it was possible to achieve reflected XSS on `mercantile.wordpress.org` with an AngularJS injection payload. This was confirmed in the latest stable Firefox and Safari builds.

---

- [Server Side Template Injection on Name parameter during Sign Up process](https://hackerone.com/reports/1104349) -- Glovo | Code Injection | 27up
- [SSTI leads to Command injection](https://hackerone.com/reports/3584149) -- curl | Command Injection - Generic | 25up
- [Client-side Template Injection in Search, user email/token leak and maybe sandbox escape](https://hackerone.com/reports/271960) -- Rockstar Games | Code Injection | 15up
- [[geekbrains.ru] Reflected XSS via Angular Template Injection](https://hackerone.com/reports/792847) -- Mail.ru | Cross-site Scripting (XSS) - Reflected | 14up
- [[marketplace.informatica.com] -  Template Injection](https://hackerone.com/reports/299241) -- Informatica | Code Injection | 12up
- [Stored xss via template injection](https://hackerone.com/reports/250837) -- WordPress | Cross-site Scripting (XSS) - Stored | 12up
- [Server-side Template Injection in lodash.js](https://hackerone.com/reports/904672) -- Node.js third-party modules | Code Injection | 8up
- [CodeQL query to detect Server-Side Template Injections (JavaScript)](https://hackerone.com/reports/894872) -- GitHub Security Lab | 8up
- [Self-DoS due to template injection via email field in password reset form on access.acronis.com](https://hackerone.com/reports/1265344) -- Acronis | 7up
- [XSS via Client Side Template Injection on www.███/News/Speeches](https://hackerone.com/reports/1736317) -- U.S. Dept Of Defense | Cross-site Scripting (XSS) - Generic | 6up
- [Server-side template injection at ujs test server](https://hackerone.com/reports/942103) -- Ruby on Rails | Command Injection - Generic | 5up
- [Java : Add query to detect Server Side Template Injection (SSTI)](https://hackerone.com/reports/1490372) -- GitHub Security Lab | 4up
- [Stored Cross-Site Scripting via Angular Template Injection](https://hackerone.com/reports/132658) -- New Relic | Cross-site Scripting (XSS) - Generic | 2up