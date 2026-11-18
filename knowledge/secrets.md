# secrets -- Top 54 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Account takeover via leaked session cookie](https://hackerone.com/reports/745324) -- HackerOne | $20,000 | Insufficiently Protected Credentials | 1642up
  > # Incident Report | 2019-11-24 Account Takeover via Disclosed Session Cookie *Last updated: 2019-11-27*  ## Issue Summary On November 24, 2019 at 13:08 UTC, HackerOne was notified through the HackerOne Bug Bounty Program by a HackerOne community member (“hacker”) that they had accessed a HackerOne Security Analyst’s HackerOne account. A session cookie was disclosed due to a human error, which...
- [CVE-2022-27774: Credential leak on redirect](https://hackerone.com/reports/1551586) -- Internet Bug Bounty | $2,400 | Insufficiently Protected Credentials | 36up
  > Curl Advisory: Credential leak on redirect Project curl Security Advisory, April 27th 2022  VULNERABILITY curl follows HTTP(S) redirects when asked to. curl also supports authentication. When a user and password are provided for a URL with a given hostname, curl makes an effort to not pass on those credentials to other hosts in redirects unless given permission with a special option.  This...
- [Shop App - Attacker is able to intercept authorization code during authentication (OAuth) and is able to get access to Microsoft Outlook email account](https://hackerone.com/reports/1700734) -- Shopify | $900 | Insufficiently Protected Credentials | 29up
  > On September 14, 2022, @kun_19 reported an issue that would allow an attacker to use a malicious app to retrieve an Outlook authorization code during authentication, due to the use of deep links. An attacker could exploit this to have access to the victim's emails.   Our engineers implemented PKCE on this login flow, mitigating the issue.
- [[█████████] Hardcoded credentials in Android App](https://hackerone.com/reports/246995) -- Eternal | $500 | Use of Hard-coded Credentials | 28up
  > Authorization credentials for one of our development environments were hard coded in our Android App. We changed it as soon as this was reported.   Thanks @gerben_javado for reporting this.
- [Uninstalling Slack for Windows (64-bit), then reinstalling keeps you logged in without authentication](https://hackerone.com/reports/238260) -- Slack | $500 | Insufficiently Protected Credentials | 18up
  > I understand that you are unlikely to consider bugs that require physical machine access, however this issue affected me directly and I was very surprised by it, so I felt it was important to report it in case it was not known.  Steps to reproduce:  1) Install the desktop Slack app for Windows (64-bit). 2) Login to Slack 3) Uninstall Slack 4) Reinstall Slack  Result: You will automatically be...
- [CVE-2022-27776: Auth/cookie leak on redirect](https://hackerone.com/reports/1551591) -- Internet Bug Bounty | $480 | Insufficiently Protected Credentials | 23up
  > Auth/cookie leak on redirect Project curl Security Advisory, April 27 2022  VULNERABILITY curl might leak authentication or cookie header data on HTTP redirects to the same host but another port number.  When asked to send custom headers or cookies in its HTTP requests, curl sends that set of headers only to the host which name is used in the initial URL, so that redirects to other hosts will...
- [Credential Disclosure via Unvalidated directDownloadUrl (Missing DontAddCredentialsAttribute)](https://hackerone.com/reports/3400143) -- Nextcloud | $250 | Insufficiently Protected Credentials | 37up
  > # Summary: The Nextcloud Desktop Client automatically includes user credentials (Authorization header with username:password in Base64) when downloading files via the `directDownloadUrl` feature. A malicious Nextcloud server can exploit this by setting `directDownloadUrl` to an attacker-controlled URL, causing the client to leak credentials to the attacker's server.  **Root Cause:** The client...
- [HackerOne Code sends live password-reset tokens to Segment in automatic page events](https://hackerone.com/reports/4000185) -- HackerOne | $200 | Insufficiently Protected Credentials | 113up
  > Opening a real HackerOne Code password-reset link automatically sends the complete unused 64-character reset token to Segment as the page loads, before the reset form is submitted. The token appears in `context.page.search`, `context.page.url`, `properties.search`, and `properties.url`. The current client parses the first query key as the reset credential and later supplies that exact value to...
- [HackerOne Code: a live password reset token reaches Datadog RUM, and the same session records the account it unlocks](https://hackerone.com/reports/4071670) -- HackerOne | $200 | Insufficiently Protected Credentials | 31up
  > ## Asset URL  https://app.pullrequest.com  ## Summary  **Opening a password reset link on `app.pullrequest.com` sends the complete, unused, 64 character reset token to Datadog, before the reset form is submitted.** The link carries the token as a bare query string key, and the Datadog RUM browser SDK on that page records `view.url` verbatim.  The SDK is initialised with **no `beforeSend`...
- [Credentials leaked via Github](https://hackerone.com/reports/1078373) -- Acronis | $50 | Use of Hard-coded Credentials | 26up
  > Hi Team,  I have found the credentials on Github which leads to direct access to the portal.  Steps to reproduce:  Go to the below link: https://github.com/MasterHimself/Test/blob/2faa2990fe2d63ceb8b1577df792e0edc5d0bdba/Selenium/Behave/Examples/Steps/Steps.py  Observed the hardcoded credentials. So, I visit the URL https://cloud.acronis.com/login & use the mentioned credentials.  ...
- [JumpCloud API Key leaked via Open Github Repository.](https://hackerone.com/reports/716292) -- Starbucks | Use of Hard-coded Credentials | 739up
  > vinothkumar discovered a publicly available Github repository containing a Starbucks JumpCloud API Key which provided access to internal system information.  @vinothkumar — thank you for reporting this vulnerability and confirming the resolution.
- [h1-202 leaderboard photo discloses local wifi password](https://hackerone.com/reports/329798) -- HackerOne | Insufficiently Protected Credentials | 145up
  > One of our photographers accidentally took a photograph that exposed the WiFi password of the H1-202 event, which we consider bad OPSEC. This photo was published on our Facebook page and the [public hackathon leaderboard](/hackathons/h1202/live). We've updated the policy regarding photographs during these events and deleted references to the password. We ended up rewarding a bounty because this...
- [Important information leaked on Github](https://hackerone.com/reports/649322) -- Equifax-vdp | Use of Hard-coded Credentials | 98up
  > While searchin on Github about Equifax i found some juicy information like a username and password of this subdomain (https://transport5.ec.equifax.com/), internal ip of the database and its username & password   In the following link (https://github.com/ajiththorali/Testing/blob/49025b364451fb2076f85ad009a0dc50a941c5ce/target/classes/API_Equifax/propertiesHandle.properties) you could find this...
- [Authentication Token Theft via Open Redirect in Callback URL Parameter](https://hackerone.com/reports/3419636) -- lemlist | Insufficiently Protected Credentials | 60up
  > An open redirect vulnerability has been identified in the email signup flow of taplio.com that enables authentication token theft through manipulation of the callback URL parameter.   The vulnerability occurs when an attacker modifies the callbackUrl parameter during the email signup process to point to an attacker-controlled domain.  When a victim completes the email verification process by...
- [Weak/Auto Fill Password](https://hackerone.com/reports/817331) -- MTN Group | Insufficiently Protected Credentials | 53up
  > Pure luck!!!  - admin/admin All login page ==MUST== be tested with admin/admin & root/root.

---

- [Credential leak on GitHub: https://github.com/█/█/ (Peoplesoft CRM)](https://hackerone.com/reports/1957430) -- 8x8 | Use of Hard-coded Credentials | 47up
- [Account takeover intercepting magic link for Arrive app](https://hackerone.com/reports/855618) -- Shopify | Insufficiently Protected Credentials | 33up
- [Cross‑origin cookies leak and injection risk when using a custom Host header](https://hackerone.com/reports/3516878) -- curl | Insufficiently Protected Credentials | 30up
- [cookie is sent on redirect](https://hackerone.com/reports/2352676) -- curl | Insufficiently Protected Credentials | 30up
- [mysql credentials exposed on - https://cz.acronis.com/docker-compose.yml](https://hackerone.com/reports/963384) -- Acronis | Insufficiently Protected Credentials | 28up
- [Exposed valid AWS, Mysql, Sendgrid and other secrets](https://hackerone.com/reports/1580567) -- Glovo | Use of Hard-coded Credentials | 22up
- [CVE-2022-27776: Auth/cookie leak on redirect](https://hackerone.com/reports/1547048) -- curl | Insufficiently Protected Credentials | 19up
- [Digest Auth State Leak on Cross-Origin Redirect via Netrc - Username and Password Hash Sent to Wrong Host](https://hackerone.com/reports/3680038) -- curl | Insufficiently Protected Credentials | 17up
- [libcurl: Improper Authentication State Management on Cross-Protocol Redirects](https://hackerone.com/reports/3514263) -- curl | Insufficiently Protected Credentials | 17up
- [CVE-2025-14524: bearer token leak on cross-protocol redirect](https://hackerone.com/reports/3459417) -- curl | Insufficiently Protected Credentials | 17up
- [Hard Coded username and password in registry](https://hackerone.com/reports/291200) -- Kaspersky | Use of Hard-coded Credentials | 17up
- [TLS conn reuse and session cache ignore fsslctx callback and ssl_config_data flags ( incomplete fix variant of 7541ae569 )](https://hackerone.com/reports/3761647) -- curl | Insufficiently Protected Credentials | 16up
- [Form Replay in customer information form](https://hackerone.com/reports/411620) -- Chaturbate | Insufficiently Protected Credentials | 16up
- [API Keys Hardcoded in Github repository](https://hackerone.com/reports/766346) -- Rocket.Chat | Use of Hard-coded Credentials | 13up
- [curl cross-origin HTTPS redirect reuses TLS client certificate for unintended second-origin mTLS authentication](https://hackerone.com/reports/3749428) -- curl | Insufficiently Protected Credentials | 11up
- [Bitbucket public repo leaking credentials from the 1C Enterprise system used by Samokat](https://hackerone.com/reports/961428) -- Mail.ru | Insufficiently Protected Credentials | 11up
- [IDOR leads to Leakage an ██████████ Login Information](https://hackerone.com/reports/1093908) -- U.S. Dept Of Defense | Insufficiently Protected Credentials | 11up
- [Hard-coded API keys at NordVpn Android App](https://hackerone.com/reports/792850) -- Nord Security | Use of Hard-coded Credentials | 11up
- [[com.smule.autorap.*] Cloud Messaging/Push Notification service takeover due to clear-text usage of Legacy FCM Server keys in the client app](https://hackerone.com/reports/789370) -- Smule | Use of Hard-coded Credentials | 10up
- [Proxy-Authorization header not cleared on cross-origin redirect in undici.request](https://hackerone.com/reports/2408074) -- Node.js | Insufficiently Protected Credentials | 9up
- [lib/ldap.c follows attacker-controlled LDAP referrals and binds to a second server; WinLDAP builds leak current logon credentials (confirmed on Window](https://hackerone.com/reports/3756699) -- curl | Insufficiently Protected Credentials | 8up
- [Testing flow includes a DeepSource secret](https://hackerone.com/reports/1927499) -- Weblate | Use of Hard-coded Credentials | 7up
- [Hardcoded AWS credentials in ███████.msi](https://hackerone.com/reports/1368690) -- 8x8 | Use of Hard-coded Credentials | 7up
- [CVE-2022-27774: Credential leak on redirect](https://hackerone.com/reports/1543773) -- curl | Insufficiently Protected Credentials | 7up
- [Insecure ███████ credentials on staging app at ████ leads to application takeover](https://hackerone.com/reports/1051885) -- U.S. Dept Of Defense | Insufficiently Protected Credentials | 7up
- [kubeadm logs tokens before deleting them](https://hackerone.com/reports/972561) -- Kubernetes | Insufficiently Protected Credentials | 7up
- [Admin Salt Leakage on DoD site.](https://hackerone.com/reports/241116) -- U.S. Dept Of Defense | Insufficiently Protected Credentials | 7up
- [nextcloud-snap CircleCI project has vulnerable configuration which can lead to exposing secrets](https://hackerone.com/reports/794407) -- Nextcloud | Insufficiently Protected Credentials | 6up
- [Possible Subdomain Takeover](https://hackerone.com/reports/233402) -- Mixmax | Insufficiently Protected Credentials | 6up
- [Credential leak on redirect](https://hackerone.com/reports/1568175) -- curl | Insufficiently Protected Credentials | 5up
- [China - Leaked credentials permitted a limited ability to create Starbucks coupons and cards](https://hackerone.com/reports/766770) -- Starbucks | Insufficiently Protected Credentials | 5up
- [Autofill/Autosave password on login](https://hackerone.com/reports/1720621) -- Yelp | Insufficiently Protected Credentials | 4up
- [Credential leak when use two url](https://hackerone.com/reports/1569926) -- curl | Insufficiently Protected Credentials | 3up
- [Improper confidentiality protection of server-side encryption keys](https://hackerone.com/reports/743505) -- Nextcloud | Insufficiently Protected Credentials | 3up
- [Sensitive Information Leaking Through DARPA Website. [█████████]](https://hackerone.com/reports/805027) -- U.S. Dept Of Defense | Insufficiently Protected Credentials | 3up
- [Sensitive Information Leaking Through DoD Owned Website. [██████████]](https://hackerone.com/reports/806213) -- U.S. Dept Of Defense | Insufficiently Protected Credentials | 3up
- [Exposed FTP Credentials on ███████](https://hackerone.com/reports/235216) -- U.S. Dept Of Defense | Insufficiently Protected Credentials | 3up
- [Improper integrity protection of server-side encryption keys](https://hackerone.com/reports/732431) -- Nextcloud | Insufficiently Protected Credentials | 2up
- [Hard coded Username and password in GiHub commit](https://hackerone.com/reports/877402) -- Kubernetes | Use of Hard-coded Credentials