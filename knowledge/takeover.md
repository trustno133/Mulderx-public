# Subdomain Takeover -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Account Takeover via Password Reset without user interactions](https://hackerone.com/reports/2293343) -- GitLab | $35,000 | Improper Access Control - Generic | 984up
  > @asterion04 submitted a report to GitLab.  Summary  I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address. Steps to reproduce  Go to "Forgot Your Password?" link Enter the victim's email and intercept the submit request via Burp Suite . Then right-click on the...
- [Account takeover via leaked session cookie](https://hackerone.com/reports/745324) -- HackerOne | $20,000 | Insufficiently Protected Credentials | 1642up
  > # Incident Report | 2019-11-24 Account Takeover via Disclosed Session Cookie *Last updated: 2019-11-27*  ## Issue Summary On November 24, 2019 at 13:08 UTC, HackerOne was notified through the HackerOne Bug Bounty Program by a HackerOne community member (“hacker”) that they had accessed a HackerOne Security Analyst’s HackerOne account. A session cookie was disclosed due to a human error, which...
- [Account Takeover via Authentication Bypass in TikTok Account Recovery](https://hackerone.com/reports/2443228) -- TikTok | $12,000 | Authentication Bypass Using an Alternate Path or Channel | 172up
  > An improper authentication mechanism in TikTok's account recovery process could have been used for account takeovers on Android devices. There was no evidence of exploitation and this vulnerability has now been completely fixed. We thank @xtt0k for reporting this to our team and confirming its remediation.
- [Ability to DOS any organization's SSO and open up the door to account takeovers](https://hackerone.com/reports/976603) -- Superhuman (formerly Grammarly) | $10,500 | Improper Authentication - Generic | 259up
  > The vulnerability was fixed before SSO became available to Grammarly customers.
- [[CRITICAL] -- Complete Account Takeover](https://hackerone.com/reports/136885) -- Uber | $8,000 | Improper Authentication - Generic | 88up
  > Thanks for another great find @parth!
- [Account Takeover via billing](https://hackerone.com/reports/394329) -- Chaturbate | $8,000 | Improper Authorization | 55up
  > The hacker found that when subscribing to a fanclub the parameters could be manipulated to purchase a fanclub subscription for another user. This will set the email of the target account if they had no email on file. This could then be used to reset the password for the target user.  The purchasing logic was fixed to not allow modifying of these parameters. The attack could only target accounts...
- [Spring Actuator endpoints publicly available, leading to account takeover](https://hackerone.com/reports/862589) -- LY Corporation | $5,000 | Misconfiguration | 143up
  > Due to insufficient access controls, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. The /heapdump endpoint leaks data from the Java Virtual Machine, leading to disclosure of admin credentials, user tokens and a combination of other data.  This endpoint was not discovered by the internal security team due to being put on a custom path, avoiding detection through...
- [[h1-2102] FQDN takeover on all Shopify wholesale customer domains by trailing dot (RFC 1034)](https://hackerone.com/reports/1086108) -- Shopify | $3,100 | Incorrect Permission Assignment for Critical Resource | 166up
  > Check out my show and tell: https://youtu.be/LSwWQPQ5IG8
- [Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties](https://hackerone.com/reports/922456) -- GitLab | $3,000 | Authentication Bypass Using an Alternate Path or Channel | 257up
  > ### Summary There's a limitation that requires a validated email before going through the OAuth flow, however this is bypassable. Bypassing this means the target site assumes your email is validated, and actually ends up signing you in with an non-validated email. This behavior can frequently lead to account takeovers in 3rd parties since they often use the email as an identifier, and fold all...
- [Account TakeOver through password recovery at am.ru](https://hackerone.com/reports/730067) -- Mail.ru | $3,000 | Improper Restriction of Authentication Attempts | 139up
- [Subdomain takeover on http://fastly.sc-cdn.net/](https://hackerone.com/reports/154425) -- Snapchat | $3,000 | Violation of Secure Design Principles | 114up
  > Hey team,  I've found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled. This allowed me to create a Fastly instance to take it over. I've confirmed this is a snapchat property via Censys (https://censys.io/certificates/65ba2e172a1eb85eb1071c9fd7a4e8371ef12625409890507c89a54978305558) though the risk here seems...
- [Stored XSS on auth.uber.com/oauth/v2/authorize via redirect_uri parameter leads to Account Takeover](https://hackerone.com/reports/397497) -- Uber | $3,000 | Cross-site Scripting (XSS) - Stored | 52up
  > By getting an authenticated victim to visit a malicious link, an attacker can cause that victim to execute arbitrary JavaScript in the context of the login.uber.com or auth.uber.com domains.
- [Hackerone supports accounts organitation takeover](https://hackerone.com/reports/2798380) -- HackerOne | $2,500 | 155up
  > ## Description: - I have discovered a vulnerability in HackerOne's email change process where the system automatically verifies the email address if the verification link is opened in any browser. This behavior differs from report #2128237, as it affects specific situations where email scanning bots automatically open links without human interaction.  - The issue arises because some email...
- [[help.steampowered.com] Account takeover bruteforcing SteamGuard](https://hackerone.com/reports/407971) -- Valve | $2,500 | Business Logic Errors | 112up
  > Due to a missing protection on a support endpoint, email verification codes could be bruteforced - leading to possible account takeover. The endpoint issue has been corrected.
- [Account takeover due to insufficient URL validation on RelayState parameter](https://hackerone.com/reports/1923672) -- GitLab | $2,450 | Cross-Site Request Forgery (CSRF) | 98up
  > Hi,   I have found an issue which can be used by an attacker to steal Bitbucket access token along with Other third party access tokens(google, salesforce etc). But the most important one is bitbucket.    Issue: =====   * there is open redirect while loggin to gitlab Via SAML, while the Open redirect is not much impactful since it is a post based request coming from third party domain, but the...

---

- [Account Takeover via Email ID Change and Forgot Password Functionality](https://hackerone.com/reports/1089467) -- New Relic | $2,048 | Improper Authentication - Generic | 214up
- [Change phone number OTP flaw leads to any phone number takeover](https://hackerone.com/reports/2588329) -- inDrive | $2,000 | Business Logic Errors | 241up
- [Account Takeover at vseapteki.ru](https://hackerone.com/reports/707231) -- Mail.ru | $2,000 | Improper Restriction of Authentication Attempts | 142up
- [Account Takeover worki.ru](https://hackerone.com/reports/744662) -- Mail.ru | $1,700 | Improper Restriction of Authentication Attempts | 391up
- [Account TakeOver at my.33slona.ru](https://hackerone.com/reports/773519) -- Mail.ru | $1,700 | Improper Restriction of Authentication Attempts | 359up
- [Staff who only have apps and channels permission can do a takeover account at the wholesale store (Bypass get invitation link)](https://hackerone.com/reports/1266828) -- Shopify | $1,600 | 53up
- [Account Takeover at worki.ru](https://hackerone.com/reports/725707) -- Mail.ru | $1,500 | Violation of Secure Design Principles | 143up
- [Support Portal Takeover via Leaked API KEY](https://hackerone.com/reports/1766228) -- AMBER AI | $1,500 | Improper Access Control - Generic | 90up
- [Account takeover at geekbrains.ru](https://hackerone.com/reports/761655) -- Mail.ru | $1,500 | Violation of Secure Design Principles | 15up
- [Chaining Bugs: Leakage of CSRF token which leads to Stored XSS and Account Takeover (xs1.tribalwars.cash)](https://hackerone.com/reports/604120) -- InnoGames | $1,100 | Insecure Storage of Sensitive Information | 186up
- [Subdomain takeover of storybook.lystit.com](https://hackerone.com/reports/779442) -- Lyst | $1,000 | Privilege Escalation | 163up
- [Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com](https://hackerone.com/reports/352869) -- Grab | $1,000 | Array Index Underflow | 142up
- [Wordpress Takeover using setup configuration at http://████.edu [HtUS]](https://hackerone.com/reports/1626205) -- U.S. Dept Of Defense | $1,000 | Misconfiguration | 102up
- [S3 bucket takeover due to proxy.harvestfiles.com](https://hackerone.com/reports/152584) -- Harvest | $1,000 | Improper Authentication - Generic | 38up
- [Account Takeover on https://www.delivery-club.ru через партнерский аккаунт.](https://hackerone.com/reports/324230) -- Mail.ru | $1,000 | Improper Authentication - Generic | 22up
- [Account takeover via Pornhub Oauth](https://hackerone.com/reports/192648) -- Pornhub | $1,000 | Improper Authentication - Generic | 17up
- [Account Takeover Vulnerability in Shopify Collabs Platform Due to Missing Email Verification](https://hackerone.com/reports/1679734) -- Shopify | $800 | 111up
- [Reflected XSS at https://pay.gold.razer.com escalated to account takeover](https://hackerone.com/reports/723060) -- Razer | $750 | Cross-site Scripting (XSS) - Reflected | 287up
- [Subdomain Takeover at test.shipt.com](https://hackerone.com/reports/387760) -- Shipt | $750 | 73up
- [Subdomain Takeover of brand.zen.ly](https://hackerone.com/reports/1474784) -- Zenly | $750 | 61up
- [Improper Authentication inside the Rockstar Games Launcher which leads to Account takeover to some extend](https://hackerone.com/reports/1442783) -- Rockstar Games | $750 | Improper Authentication - Generic | 51up
- [Organization Takeover](https://hackerone.com/reports/809816) -- Helium | $500 | Improper Access Control - Generic | 263up
- [Subdomain takeover of resources.hackerone.com](https://hackerone.com/reports/863551) -- HackerOne | $500 | 95up
- [Subdomain takeover on a subdomain under firefox.com](https://hackerone.com/reports/2899858) -- Mozilla | $500 | Misconfiguration | 75up
- [Subdomain Takeover Via unclaimed Heroku Instance tim-exclusive.shopify.com](https://hackerone.com/reports/424669) -- Shopify | $500 | Improper Authentication - Generic | 68up
- [Deprecated Hacker101 coursework repository mentions Heroku App that is susceptible to takeover](https://hackerone.com/reports/514451) -- HackerOne | $500 | Externally Controlled Reference to a Resource in Another Sphere | 68up
- [[ addons-preview-cdn.mozilla.net ] A subdomain takeover is available via unregistered domain in Fastly](https://hackerone.com/reports/2706358) -- Mozilla | $500 | Misconfiguration | 66up
- [Subdomain takeover of www█████████.affirm.com](https://hackerone.com/reports/1297689) -- Affirm | $500 | Business Logic Errors | 55up
- [Sub-Domain Takeover at   http://www.codefi.consensys.net/](https://hackerone.com/reports/1717626) -- MetaMask | $500 | Improper Access Control - Generic | 42up
- [Full Account Takeover In ****.ru](https://hackerone.com/reports/1078479) -- Mail.ru | $500 | Authentication Bypass Using an Alternate Path or Channel | 35up
- [4 Subdomains Takeover on 2 domains ( muberscolombia.com &  ubereats.pl )](https://hackerone.com/reports/1116545) -- Uber | $500 | Privilege Escalation | 29up
- [Domain Takeover of Reddit.ru via DNS Hijacking](https://hackerone.com/reports/1226891) -- Reddit | $500 | Improper Access Control - Generic | 20up
- [Partner Account Takeover on https://www.delivery-club.ru через пользовательский аккаунт.](https://hackerone.com/reports/330760) -- Mail.ru | $500 | Improper Authentication - Generic | 14up
- [[supportlocal.delivery-club.ru] Subdomain Takeover](https://hackerone.com/reports/1054765) -- Mail.ru | $500 | 13up
- [Subdomain takeover on s3.shopify.com](https://hackerone.com/reports/207576) -- Shopify | $500 | Cross-site Scripting (XSS) - Generic | 13up
- [Full Account Takeover Student Account In https://********.ru/signin/main/student/email](https://hackerone.com/reports/1079275) -- Mail.ru | $500 | Authentication Bypass Using an Alternate Path or Channel | 9up
- [mrgs.my.games account takeover](https://hackerone.com/reports/999314) -- Mail.ru | $500 | Improper Access Control - Generic | 4up
- [URGENT - Subdomain Takeover on users.tweetdeck.com , the same issue  of report #32825](https://hackerone.com/reports/42236) -- X / xAI | $420 | Code Injection | 4up
- [Subdomain takeover of fr1.vpn.zomans.com](https://hackerone.com/reports/1182864) -- Eternal | $350 | Business Logic Errors | 99up
- [Mystery with a leaked token and Reusability of email confirmation link leading to Account Takeover](https://hackerone.com/reports/1817214) -- Sorare | $300 | Inadequate Encryption Strength | 49up
- [Account takeover by using  abandoned email id of victim which has already been changed to new  by victim himself on one.newrelic.com](https://hackerone.com/reports/1021232) -- New Relic | $300 | Improper Authentication - Generic | 38up
- [jsConnect Plugin: Takeover of existing account](https://hackerone.com/reports/384962) -- Vanilla | $300 | Improper Authentication - Generic | 35up
- [Subdomain takeover at segway.shipt.com](https://hackerone.com/reports/389783) -- Shipt | $300 | 23up
- [Subdomain Takeover Via via Dangling NS records on Amazon Route 53 http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io](https://hackerone.com/reports/746000) -- Kubernetes | $250 | Improper Authentication - Generic | 62up
- [Subdomain Takeover via unclaimed UserVoice domain](https://hackerone.com/reports/269109) -- Snapchat | $250 | Privilege Escalation | 18up
- [AWS subdomain Takeover at estore.razersynapse.com](https://hackerone.com/reports/785179) -- Razer | $250 | Privilege Escalation | 15up
- [Subdomain takeover at ftp.thx.com](https://hackerone.com/reports/703591) -- Razer | $250 | Privilege Escalation | 15up
- [Helpdesk takeover (subdomain takeover) in razerzone.com domain via unclaimed Zendesk instance](https://hackerone.com/reports/810807) -- Razer | $250 | Misconfiguration | 12up
- [Subdomain takeover on slack.augur.net pointing to GitHub Pages](https://hackerone.com/reports/382995) -- Augur | $250 | Privacy Violation | 12up
- [clickjacing can lead to account takeover](https://hackerone.com/reports/2119892) -- pixiv | $200 | UI Redressing (Clickjacking) | 70up
- [session takeover via open protocol redirection on streamlabs.com](https://hackerone.com/reports/1178239) -- Logitech | $200 | Open Redirect | 50up
- [Subdomain Takeover via Unclaimed Amazon S3 Bucket (Musical.ly)](https://hackerone.com/reports/1102537) -- TikTok | $200 | Privilege Escalation | 29up
- [Domain Takeover - gl-canary.freetls.fastly.net](https://hackerone.com/reports/716677) -- GitLab | $200 | Privilege Escalation | 25up
- [Subdomain takeover at iosota.razersynapse.com via Amazon S3](https://hackerone.com/reports/813313) -- Razer | $200 | Privilege Escalation | 18up
- [Account TakeOver at kvartira.city-mobil.ru](https://hackerone.com/reports/1004360) -- Mail.ru | $150 | Improper Restriction of Authentication Attempts | 18up
- [Sub Domain Takeover at mk.prd.vine.co](https://hackerone.com/reports/191323) -- X / xAI | $140 | 7up
- [Potential Subdomain Takeover Possible](https://hackerone.com/reports/166826) -- Boozt Fashion AB | $120 | 14up
- [Subdomain takeover of main domain of https://www.cyberlynx.lu/](https://hackerone.com/reports/1256389) -- Acronis | $100 | Privilege Escalation | 70up
- [Organization Takeover via invitation API](https://hackerone.com/reports/835005) -- Helium | $100 | Insecure Direct Object Reference (IDOR) | 40up
- [Subdomain takeover on podcasts.slack-core.com](https://hackerone.com/reports/195350) -- Slack | $100 | Cross-site Scripting (XSS) - Generic | 27up
- [Broken Domain Link Takeover from kubernetes.io docs](https://hackerone.com/reports/1434179) -- Kubernetes | $100 | Insecure Temporary File | 17up
- [Subdomain Takeover uptime](https://hackerone.com/reports/824909) -- BTFS | $100 | Privilege Escalation | 14up
- [Subdomain Takeover in http://staging.wepay.com/ pointing to Fastly](https://hackerone.com/reports/93106) -- WePay | $100 | Privilege Escalation | 2up
- [Subdomain takeover http://accessday.opn.ooo/](https://hackerone.com/reports/1963213) -- Omise | $50 | Improper Access Control - Generic | 74up
- [Bruteforcing password reset tokens, could lead to account takeover](https://hackerone.com/reports/271533) -- Instacart | $50 | Improper Restriction of Authentication Attempts | 14up
- [Takeover an account that doesn't have a Shopify ID and more](https://hackerone.com/reports/867513) -- Shopify | 3005up
- [Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies](https://hackerone.com/reports/737140) -- Slack | HTTP Request Smuggling | 868up
- [Subdomain Takeover to Authentication bypass](https://hackerone.com/reports/335330) -- Roblox | 782up
- [Bypassing Digits origin validation which leads to account takeover](https://hackerone.com/reports/129873) -- X / xAI | Improper Authentication - Generic | 619up
- [RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/](https://hackerone.com/reports/502758) -- Starbucks | Code Injection | 572up
- [Request smuggling on admin-official.line.me could lead to account takeover](https://hackerone.com/reports/740037) -- LY Corporation | HTTP Request Smuggling | 564up
- [Flickr Account Takeover using AWS Cognito API](https://hackerone.com/reports/1342088) -- Flickr | Improper Authentication - Generic | 440up
- [Full account takeover](https://hackerone.com/reports/314808) -- Reverb.com | Improper Access Control - Generic | 411up
- [Physical Laptop Takeover](https://hackerone.com/reports/393615) -- Ed | Privacy Violation | 380up
- [CVE-2019-5765: 1-click HackerOne account takeover on all Android devices](https://hackerone.com/reports/563870) -- Chrome | 375up
- [H1514 Ability to MiTM Shopify PoS Session to Takeover Communications](https://hackerone.com/reports/423467) -- Shopify | Business Logic Errors | 372up
- [[CSRF] TikTok Careers Portal Account Takeover](https://hackerone.com/reports/1010522) -- TikTok | Cross-Site Request Forgery (CSRF) | 366up
- [[cs.money] Open Redirect Leads to Account Takeover](https://hackerone.com/reports/905607) -- CS Money | Improper Authentication - Generic | 356up
- [Subdomain takeover of datacafe-cert.starbucks.com](https://hackerone.com/reports/665398) -- Starbucks | Privilege Escalation | 311up
- [Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)](https://hackerone.com/reports/143717) -- Uber | Improper Authentication - Generic | 311up
- [Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation](https://hackerone.com/reports/796956) -- Shopify | 310up
- [Account takeover through the combination of cookie manipulation and XSS](https://hackerone.com/reports/534450) -- Superhuman (formerly Grammarly) | Cross-site Scripting (XSS) - Stored | 291up
- [[CRITICAL] 0-Click Account Takeover via Password Reset [AUTH-3243] /orchestrator/v1/password_reset/start](https://hackerone.com/reports/2831902) -- Remitly | Improper Access Control - Generic | 285up
- [Insufficient OAuth callback validation which leads to Periscope account takeover](https://hackerone.com/reports/110293) -- X / xAI | Improper Authentication - Generic | 276up
- [Singapore - Account Takeover via IDOR](https://hackerone.com/reports/876300) -- Starbucks | Insecure Direct Object Reference (IDOR) | 260up