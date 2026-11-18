# CORS -- Top 64 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [[www.zomato.com] CORS Misconfiguration, could lead to disclosure of sensitive information](https://hackerone.com/reports/426165) -- Eternal | $550 | 246up
  > ## Summary: Cross Origin Resource Sharing Misconfiguration | Lead to sensitive information.  ## Description: An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other...
- [Exploiting Misconfigured CORS to Steal User Information](https://hackerone.com/reports/317391) -- Rockstar Games | $500 | Information Disclosure | 36up
  > In this report, the researcher demonstrated how a CORS misconfiguration was allowing user details, such as email addresses and IDs, to be shared inappropriately. They also provided a POC which showed how an attacker could exploit this remotely. This issue was resolved in a platform update to our Support site; the gateway that was leaking user information was removed entirely.
- [Permissive CORS policy trusting arbitrary extensions origin](https://hackerone.com/reports/412490) -- Superhuman (formerly Grammarly) | $500 | Improper Access Control - Generic | 33up
  > @foobar7 identified that misconfigurations in CORS and CSRF handling allowed malicious browser extensions, which have permission to interact with `grammarly.com` domain, to impersonate the user.  The vulnerability was resolved with improved CSRF/CORS handling.
- [Site-wide CSRF on Safari due to CORS misconfiguration (not localhost)](https://hackerone.com/reports/975983) -- CS Money | $300 | Cross-Site Request Forgery (CSRF) | 33up
  > ## Description Hello there, on `new.cs.money` or `cs.money`, there is anti-CSRF mechanism, which is `Referer` header check. However, I discovered that regex logic for checking `Referer` header is flawed.  I found that adding `{` or `}` at the end of the domain pass the validation. Therefore, if a request comes from `new.cs.money{.attacker.com` it would pass validation. And because there is no...
- [CORS bypass on TikTok Ads Endpoint](https://hackerone.com/reports/1001951) -- TikTok | $257 | Misconfiguration | 19up
  > An endpoint used by the TikTok Ads portal was vulnerable to CORS bypass therefore potentially allowing an attacker to access information about tickets opened if the user were to click on a malicious link. We thank @sniper302 for reporting this to our team and confirming the resolution!
- [Cross-origin resource sharing](https://hackerone.com/reports/1478449) -- Showmax | $50 | 13up
- [Denial of service to WP-JSON API by cache poisoning the CORS allow origin header](https://hackerone.com/reports/591302) -- Automattic | Uncontrolled Resource Consumption | 405up
  > The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary `Origin` header in the request, which is then echoed back in the response via the `Access-Control-Allow-Origin` header, which is cached and served to other requests.  This response header is used by browsers to determine whether the requesting...
- [Bypassing CORS Misconfiguration Leads to Sensitive Exposure](https://hackerone.com/reports/768151) -- U.S. Dept Of Defense | Business Logic Errors | 145up
  > **Hi!** Security Team @deptofdefense,  It's possible to get information about the users registered (such as: id, name, login name, etc.) without authentication in  Wordpress via API on  *. ███████.  ***Description:*** By default Wordpress allow public access to Rest API to get informations about all users registered on the system.  Platform(s) Affected: [website] *....
- [Cross-origin resource sharing misconfig - steal user information](https://hackerone.com/reports/235200) -- Semrush | Misconfiguration | 97up
  > Man, treat you another drink.   ## Description  An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request. Trusting arbitrary origins effectively...
- [CORS misconfiguration allows to steal client's "password", Authorization token and the customer details e.g. names, SSN, bank account etc.](https://hackerone.com/reports/688567) -- LocalTapiola | 86up
- [CORS misconfiguration allows to steal customers data](https://hackerone.com/reports/577969) -- LocalTapiola | Violation of Secure Design Principles | 84up
- [CORS misconfiguration leads to users information disclosure at https://studyroom.line.me](https://hackerone.com/reports/924951) -- LY Corporation | Information Disclosure | 73up
  > Due to the CORS(Cross-Origin Resource Sharing) misconfiguration in the StudyRoom API server, SOP(Same Origin Policy) can be bypassed, and the API that retrieves one's profile information was returning more personal information than necessary. Combining the issues allows an attacker to obtain user information when a user clicks an URL of a maliciously crafted web page. This vulnerability could...
- [CORS misconfiguration in TikTok ads portal](https://hackerone.com/reports/1006524) -- TikTok | Improper Access Control - Generic | 69up
  > A CORS misconfiguration was discovered in the TikTok ads portal which could potentially allow an attacker to obtain user IDs and usernames of logged in users. This issue has been resolved. We thank @chihuahua for reporting this to our team.
- [CORS Misconfiguration leading to Private Information Disclosure](https://hackerone.com/reports/430249) -- Ubiquiti Inc. | Improper Access Control - Generic | 57up
  > Due to mistake on te CORS policy configuration, the sites https://client.amplifi.com and https://protect.ubnt.com/ CORS policy allowed HTTP requests to be made from certain sites outside the `*.ubnt.com` and `*.ui.com` domains.  This bug could be used to steal users information or force the user to execute unwanted actions. As long that a legit and logged in user is lure to access a attacker...
- [CORS misconfiguration which leads to the disclosure of certain data concerning the user.](https://hackerone.com/reports/769058) -- Semrush | Improper Access Control - Generic | 46up
  > # INTRODUCTION  ## _I used an account to search for this vulnerability:_  id: 5407773	email: adam-bugbounty@anosimple.com  ## _IP used:_ __2a01:e34:ec2a:9240:7d25:26c3:1449:bfe7__  ## _endpoint URL:_ https://www.semrush.com/content-paywall/api/accesslevel  ## _Summary:_ CORS policy too permissive.  # EXPLOITATION  ## _Description of Security Issue:_  When we navigate on semrush we are led to...

---

- [Myndr CORS Misconfiguration](https://hackerone.com/reports/3930957) -- Myndr | Improper Access Control - Generic | 36up
- [[██████] Cross-origin resource sharing misconfiguration (CORS)](https://hackerone.com/reports/470298) -- U.S. Dept Of Defense | Improper Access Control - Generic | 34up
- [CORS Misconfiguration, could lead to disclosure of users information](https://hackerone.com/reports/879582) -- Xiaomi | 33up
- [CORS Misconfiguration on www.zomato.com](https://hackerone.com/reports/168574) -- Eternal | 31up
- [CORS misconfig - Account Takeover](https://hackerone.com/reports/426147) -- X / xAI | 30up
- [Corss-Tenant IDOR on Business allowing escalation privilege, invitation takeover, and edition of any other Businesses' employees](https://hackerone.com/reports/1063022) -- Uber | Privilege Escalation | 29up
- [CORS Misconfiguration / Broken Access Control](https://hackerone.com/reports/3930102) -- Myndr | Improper Access Control - Generic | 21up
- [CORS Misconfiguration on nordvpn.com leading to Private Information Disclosure,Account takeover](https://hackerone.com/reports/758785) -- Nord Security | Improper Access Control - Generic | 21up
- [CORS Misconfiguration on Yelp](https://hackerone.com/reports/1707616) -- Yelp | 19up
- [Blind XSS Stored and CORS misconfiguration в отчете "События" сервиса top.mail.ru](https://hackerone.com/reports/1255676) -- Mail.ru | Cross-site Scripting (XSS) - Stored | 19up
- [Account takeover via CORS misconfigutation on https://beta.delivery-club.ru](https://hackerone.com/reports/685032) -- Mail.ru | 18up
- [Denial-of- service By Cache Poisoning The Cross-Origin Resource Sharing Misconfiguration Allow Origin Header](https://hackerone.com/reports/921704) -- Automattic | Uncontrolled Resource Consumption | 17up
- [Unsafe cors sharing of admin users](https://hackerone.com/reports/772744) -- MTN Group | 17up
- [CORS Misconfiguration in https://████████/accounts/login/](https://hackerone.com/reports/1771149) -- U.S. Dept Of Defense | Improper Access Control - Generic | 15up
- [Cross-origin resource sharing misconfig - steal user information](https://hackerone.com/reports/1183601) -- UPchieve | Information Disclosure | 15up
- [CORS misconfiguration which leads to the disclosure](https://hackerone.com/reports/1005374) -- U.S. Dept Of Defense | Improper Access Control - Generic | 15up
- [(CORS) Cross-origin resource sharing misconfiguration](https://hackerone.com/reports/896093) -- U.S. Dept Of Defense | Business Logic Errors | 14up
- [CORS Misconfiguration on vanillaforums.com](https://hackerone.com/reports/1527555) -- Vanilla | 13up
- [Cross-origin resource sharing: arbitrary origin trusted on chatws25.stream.highwebmedia.com](https://hackerone.com/reports/417453) -- Chaturbate | Improper Access Control - Generic | 13up
- [Cross-origin resource sharing (CORS)](https://hackerone.com/reports/272432) -- Aspen | Improper Access Control - Generic | 12up
- [[dev-unifi-go.ubnt.com] Insecure CORS, Stealing Cookies](https://hackerone.com/reports/219014) -- Ubiquiti Inc. | Information Exposure Through an Error Message | 12up
- [CORS Misconfiguration](https://hackerone.com/reports/1194280) -- Sifchain | Misconfiguration | 11up
- [CORS on (ws.infogram.com)](https://hackerone.com/reports/372452) -- Infogram | Improper Access Control - Generic | 11up
- [CORS Misconfiguration, could lead to disclosure of sensitive information](https://hackerone.com/reports/1199527) -- UPchieve | Wrap-around Error | 10up
- [CORS (Cross-Origin Resource Sharing)](https://hackerone.com/reports/163491) -- Legal Robot | Improper Authentication - Generic | 9up
- [CORS misconfiguration](https://hackerone.com/reports/1187543) -- Sifchain | Business Logic Errors | 8up
- [CORS Misconfiguration Leads to Sensitive Exposure on  Sifchain main domain](https://hackerone.com/reports/1188684) -- Sifchain | 8up
- [(CORS) Cross-origin resource sharing misconfiguration on https://█████████](https://hackerone.com/reports/995144) -- U.S. Dept Of Defense | Business Logic Errors | 7up
- [Bypassing CORS Misconfiguration Leads to Sensitive Exposure at https://███/](https://hackerone.com/reports/1092125) -- U.S. Dept Of Defense | Violation of Secure Design Principles | 6up
- [NR-wide cross account access through misconfigured CORS-policy of multiple endpoints](https://hackerone.com/reports/751699) -- New Relic | Improper Access Control - Generic | 6up
- [CORS Misconfiguration Leads to Exposing User Data](https://hackerone.com/reports/733017) -- U.S. Dept Of Defense | Improper Access Control - Generic | 6up
- [CORS (Cross-Origin Resource Sharing)](https://hackerone.com/reports/310579) -- Semrush | Improper Authentication - Generic | 6up
- [Cross-origin resource sharing misconfig](https://hackerone.com/reports/311805) -- Semrush | Improper Authentication - Generic | 6up
- [CORS Misconfiguration](https://hackerone.com/reports/1530581) -- U.S. Dept Of Defense | Violation of Secure Design Principles | 5up
- [CORS origin validation failure](https://hackerone.com/reports/1404986) -- UPchieve | 5up
- [CORS (Cross-Origin Resource Sharing) origin validation failure -Any website can issue requests made with user credentials and read the responses to th](https://hackerone.com/reports/1188471) -- Sifchain | Cross-site Scripting (XSS) - Stored | 5up
- [[mattermost.com] CORS Misconfiguration leakage of admin users](https://hackerone.com/reports/1113759) -- Mattermost | Information Disclosure | 5up
- [CORS Misconfiguration on trust.yelp.com](https://hackerone.com/reports/1716286) -- Yelp | 4up
- [Java: CWE-346 Queries to detect remote source flow to CORS Headers](https://hackerone.com/reports/1133574) -- GitHub Security Lab | 4up
- [misconfigured CORS let to HPP and SOP bypass](https://hackerone.com/reports/867436) -- BTFS | Misconfiguration | 4up
- [Cross-origin resource sharing](https://hackerone.com/reports/288912) -- Semrush | 4up
- [HTML5 cross-origin resource sharing](https://hackerone.com/reports/13551) -- Factlink | 4up
- [Corsa Site Scripting Vulnerability (XSS)](https://hackerone.com/reports/1650210) -- Linux Foundation Decentralized Trust | Cross-site Scripting (XSS) - Reflected | 3up
- [CORS (Cross-Origin Resource Sharing) origin validation failure](https://hackerone.com/reports/1192147) -- Sifchain | 3up
- [[go]: Add query for detecting CORS misconfiguration](https://hackerone.com/reports/1266540) -- GitHub Security Lab | 3up
- [Cross-origin resource sharing misconfiguration (CORS)](https://hackerone.com/reports/954512) -- Brave Software | Improper Access Control - Generic | 3up
- [looch.tv CORS crossite user information and stream_key access](https://hackerone.com/reports/708886) -- Mail.ru | Cross-Site Request Forgery (CSRF) | 3up
- [Disclosure of locally served nerdpacks due to nr-local.net CORS policy misconfiguration](https://hackerone.com/reports/746786) -- New Relic | Information Disclosure | 2up
- [CORS on my.stripo.email](https://hackerone.com/reports/859688) -- Stripo Inc | 1up