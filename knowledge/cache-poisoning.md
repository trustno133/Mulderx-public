# Cache Poisoning -- Top 68 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) -- PayPal | $18,900 | HTTP Request Smuggling | 684up
  > Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages,...
- [DoS on PayPal via web cache poisoning](https://hackerone.com/reports/622122) -- PayPal | $9,700 | Uncontrolled Resource Consumption | 851up
  > On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'. This was patched and awarded a $9,700 bounty.
- [DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com](https://hackerone.com/reports/1695604) -- Shopify | $3,800 | Cache Poisoning | 265up
  > A web cache poisoning vulnerability was discovered on Shopify's CDN domains where cache servers treated backslashes and forward slashes as equivalent while origin servers returned 404 errors for paths with backslashes. This discrepancy allowed an attacker to send requests with backslashes instead of forward slashes, causing 404 errors to be cached and served for legitimate requests, creating a...
- [https://themes.shopify.com::: Host header web cache poisoning lead to DoS](https://hackerone.com/reports/1096609) -- Shopify | $2,900 | Uncontrolled Resource Consumption | 82up
  > Hi there, I just found the website: https://themes.shopify.com is infected with "Web cache poisoning" via HOST header lead to Denial of Services Abuse this bug, Attacker can:  Poison your cache with HTTP header Host header with arbitrary PORT which is not opened. This attack may lead to Denial of Services  How to reproduce the issue: In the 1st terminal, run command likes this: ---------- $...
- [Denial of service via cache poisoning](https://hackerone.com/reports/409370) -- HackerOne | $2,500 | Uncontrolled Resource Consumption | 253up
  > An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port.  To replicate:  ```curl -H 'X-Forwarded-Port: 123' https://www.hackerone.com/index.php?dontpoisoneveryone=1``` Then try to load https://www.hackerone.com/index.php?dontpoisoneveryone=1 in your...
- [Cache poisoning via X-Forwarded-Host in www.shopify.com/partners/blog](https://hackerone.com/reports/977851) -- Shopify | $1,000 | Improper Neutralization of HTTP Headers for Scripting Syntax | 67up
  > Hello, run in loop requests with```  X-Forwarded-Host: your_hackerz_site.com ``` - after some time You will notice in response ``` your_hackerz_site.com ```  {F981839}  now remove ``` X-Forwarded-Host  ``` - there still be our url:  {F981841}  i've logged to my VPS to verify this bug and downloaded poisoned page...
- [Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage](https://hackerone.com/reports/1271944) -- Shopify | $800 | Violation of Secure Design Principles | 48up
  > # Shopify.com Web Cache Deception Vulnerability  **Matteo Golinelli, July 21, 2021**. <█████████> <████>  I am testing websites for possible Web Cache Deception vulnerabilities (you can find more about it [here](https://portswigger.net/daily-swig/path-confusion-web-cache-deception-threatens-user-information-online)) and I discovered that `shopify.com` is vulnerable.  Web cache deception (WCD)...
- [Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS](https://hackerone.com/reports/303730) -- GSA Bounty | $750 | Cross-site Scripting (XSS) - Stored | 93up
  > An attacker can deface various pages on catalog.data.gov, leading to them executing malicious JavaScript when visited by a normal user.  The root problem is that the server trusts the X-Forwarded-Host HTTP header, and uses this to populate the 'data-site-root' and 'data-locale-root' attributes on the <body tag. Some JavaScript then fetches a JSON file from the URL specified in these attributes,...
- [Cache Poisoning via uppercase letters in invalid path](https://hackerone.com/reports/960618) -- InnoGames | $550 | Violation of Secure Design Principles | 82up
- [Web cache poisoning attack leads to user information and more](https://hackerone.com/reports/492841) -- Postmates | $500 | Violation of Secure Design Principles | 343up
- [URL Path Manipulation Enables Cache Poisoning of Amazon Affiliate Products in Shopify Linkpop](https://hackerone.com/reports/1848940) -- Shopify | $500 | Cache Poisoning | 86up
  > A cache poisoning vulnerability in Shopify's Linkpop allowed attackers to manipulate Amazon affiliate product displays through specially crafted URLs. When victims added legitimate Amazon products, they would unknowingly display the attacker's products instead. In the end, this low severity issue was not fixed as the Linkpop service was scheduled for decommissioning on July 7, 2025.
- [Web Cache Deception vulnerability on algolia.com leads to personal information leakage](https://hackerone.com/reports/1530066) -- Algolia | $400 | Violation of Secure Design Principles | 46up
  > A web cache deception(WCD) was found on our main website (algolia.com). An attacker could trick a caching proxy into storing private information transmitted over the internet from authenticated user. To do so, attacker would use simple social engineering where the victim is only required to open a link in a browser while being authenticated on the website. The attacker could then access the...
- [Web Cache Deception Attack (XSS)](https://hackerone.com/reports/394016) -- Discourse | $256 | Cross-site Scripting (XSS) - Stored | 51up
  > * Web Cache Poisoning ===
- [Web cache deception attack on https://open.vanillaforums.com/messages/all](https://hackerone.com/reports/593712) -- Vanilla | $150 | Information Disclosure | 47up
- [DNS Cache Poisoning](https://hackerone.com/reports/487) -- HackerOne | $100 | 41up
  > I noticed if I made a request to your website, intercepted the request, and added the header... X-Forwarded-Host: evil.com it would redirect me to evil.com. Well, after that, I tried going to hackerone.com and I was instantly redirected to evil.com. This is a result of DNS cache poisoning.

---

- [Denial of service to WP-JSON API by cache poisoning the CORS allow origin header](https://hackerone.com/reports/591302) -- Automattic | Uncontrolled Resource Consumption | 405up
- [Static files on HackerOne.com can be made inaccessible through Cache Poisoning attack](https://hackerone.com/reports/1181946) -- HackerOne | Uncontrolled Resource Consumption | 228up
- [Cache Poisoning allows redirection on JS files](https://hackerone.com/reports/1795197) -- Glassdoor | Cross-site Scripting (XSS) - Stored | 219up
- [XSS and cache poisoning via upload.twitter.com on ton.twitter.com](https://hackerone.com/reports/84601) -- X / xAI | Cross-site Scripting (XSS) - Generic | 198up
- [Cache Deception Allows Account Takeover](https://hackerone.com/reports/1698316) -- Expedia Group Bug Bounty | Use of Cache Containing Sensitive Information | 159up
- [Web Cache Poisoning leads to Stored XSS](https://hackerone.com/reports/1424094) -- Glassdoor | Cross-site Scripting (XSS) - Stored | 133up
- [Cache Poisoning Allows Stored XSS Via hav Cookie Parameter (To Account Takeover)](https://hackerone.com/reports/1760213) -- Expedia Group Bug Bounty | Cross-site Scripting (XSS) - Stored | 117up
- [Cache Poisoning DoS on downloads.exodus.com](https://hackerone.com/reports/1173153) -- Exodus | Uncontrolled Resource Consumption | 110up
- [Cache poisoning Denial of Service affecting assets.gitlab-static.net](https://hackerone.com/reports/1160407) -- GitLab | Uncontrolled Resource Consumption | 83up
- [Cache Poisoning DoS on updates.rockstargames.com](https://hackerone.com/reports/1219038) -- Rockstar Games | Violation of Secure Design Principles | 77up
- [Bypass of Cloudflare's Cache Keys and WAF via header overflow](https://hackerone.com/reports/3027461) -- Cloudflare Public Bug Bounty | Improper Access Control - Generic | 76up
- [Web Cache Poisoning leads to XSS and DoS](https://hackerone.com/reports/1621540) -- Glassdoor | Cross-site Scripting (XSS) - Stored | 71up
- [web cache deception in https://tradus.com lead to name/user_id enumeration and other info](https://hackerone.com/reports/537564) -- OLX | Violation of Secure Design Principles | 63up
- [Web Cache Deception](https://hackerone.com/reports/2265400) -- Glassdoor | Information Disclosure | 62up
- [[https://www.glassdoor.com] -  Web Cache Deception Leads to gdtoken Disclosure](https://hackerone.com/reports/1343086) -- Glassdoor | Information Disclosure | 60up
- [CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)](https://hackerone.com/reports/260697) -- Discourse | Cross-Site Request Forgery (CSRF) | 58up
- [Docker Secret Disclosure via GitHub Actions Cache Poisoning](https://hackerone.com/reports/2410111) -- Linux Foundation Decentralized Trust | Information Disclosure | 56up
- [DOS via cache poisoning on [developer.mozilla.org]](https://hackerone.com/reports/1976449) -- Mozilla | Cache Poisoning | 55up
- [Web Cache poisoning attack leads to User information Disclosure and more](https://hackerone.com/reports/631589) -- Lyst | Violation of Secure Design Principles | 45up
- [Cache Pollution via Unkeyed GET Parameters on www.omise.co](https://hackerone.com/reports/3183046) -- Omise | 43up
- [Web cache poisoning leads to disclosure of CSRF token and sensitive information](https://hackerone.com/reports/504514) -- Smule | Violation of Secure Design Principles | 39up
- [Bypassing Cache Deception Armor using .avif extension file](https://hackerone.com/reports/1391635) -- Cloudflare Public Bug Bounty | Information Disclosure | 36up
- [Web Cache Poisoning on  █████](https://hackerone.com/reports/1183263) -- U.S. Dept Of Defense | Violation of Secure Design Principles | 36up
- [[allods.mail.ru] - WebCache Poisoning Host Header lead to Potential Stored XSS](https://hackerone.com/reports/1262408) -- Mail.ru | Cross-site Scripting (XSS) - Stored | 35up
- [Cache poisoning using NULL bytes and long URLs](https://hackerone.com/reports/334709) -- Greenhouse.io | Improper Null Termination | 32up
- [Web cache poisoning at www.acronis.com](https://hackerone.com/reports/1010858) -- Acronis | Violation of Secure Design Principles | 29up
- [HTTP request smuggling on Basecamp 2 allows web cache poisoning](https://hackerone.com/reports/919175) -- Basecamp | HTTP Request Smuggling | 28up
- [Web cache deception attack - expose token information](https://hackerone.com/reports/397508) -- Chaturbate | Information Disclosure | 28up
- [Web Cache Deception Attack (XSS)](https://hackerone.com/reports/504261) -- Algolia | Cross-site Scripting (XSS) - Reflected | 26up
- [Cache poisoning DoS to various TTS assets](https://hackerone.com/reports/728664) -- GSA Bounty | Violation of Secure Design Principles | 25up
- [https://help.nextcloud.com::: Web cache poisoning attack](https://hackerone.com/reports/429747) -- Nextcloud | 25up
- [Denial of Access to Static Resources via Cache Poisoning on addons.allizom.org](https://hackerone.com/reports/2860983) -- Mozilla | Cache Poisoning | 24up
- [Bypass of request line length limit to DoS via cache poisoning](https://hackerone.com/reports/350847) -- Greenhouse.io | Uncontrolled Resource Consumption | 24up
- [DoS through cache poisoning using invalid HTTP parameters](https://hackerone.com/reports/326639) -- Greenhouse.io | Uncontrolled Resource Consumption | 24up
- [[*.rocketbank.ru] Web Cache Deception & XSS](https://hackerone.com/reports/415168) -- QIWI | Cross-site Scripting (XSS) - Stored | 21up
- [Several domains on kaspersky.com are vulnerable to Web Cache Deception attack](https://hackerone.com/reports/1185028) -- Kaspersky | Insecure Storage of Sensitive Information | 20up
- [PROTOCOL-LEVEL: Persistent UDP Amplification and Cache Poisoning via Alt-Svc Logic Flaw](https://hackerone.com/reports/3483902) -- curl | Business Logic Errors | 19up
- [Web Cache Poisoning leading to DoS](https://hackerone.com/reports/1346618) -- U.S. General Services Administration | Uncontrolled Resource Consumption | 19up
- [Server-side cache poisoning leads to the http://my.dev.owox.com inaccessibility](https://hackerone.com/reports/291012) -- OWOX, Inc. | 18up
- [Denial-of- service By Cache Poisoning The Cross-Origin Resource Sharing Misconfiguration Allow Origin Header](https://hackerone.com/reports/921704) -- Automattic | Uncontrolled Resource Consumption | 17up
- [Web Cache Poisoning](https://hackerone.com/reports/534297) -- Mail.ru | Cross-site Scripting (XSS) - Stored | 17up
- [CSRF on developer.zendesk.com via Cache Deception](https://hackerone.com/reports/423986) -- Zendesk | 15up
- [Information Leakage via TikTok Ads Web Cache Deception](https://hackerone.com/reports/1484468) -- TikTok | Misconfiguration | 14up
- [Cache Poisoning](https://hackerone.com/reports/824753) -- Internet Bug Bounty | Improper Handling of URL Encoding (Hex Encoding) | 14up
- [Denial of service via cache poisoning on https://www.data.gov/](https://hackerone.com/reports/942629) -- GSA Bounty | 12up
- ['X-Forwarded-Host' key used in input without sanitation - possible cache poisoning](https://hackerone.com/reports/737315) -- Radancy | Resource Injection | 10up
- [Web cache deception attack - expose earning state information](https://hackerone.com/reports/439021) -- Semrush | Improper Access Control - Generic | 10up
- [Default behavior of Fastifys versioned routes can be used for cache poisoning when Fastify is used in combination with a http cache / CDN](https://hackerone.com/reports/1025575) -- Node.js third-party modules | HTTP Request Smuggling | 8up
- [2 Cache Poisoning Attack Methods Affect Core Functionality www.exodus.com](https://hackerone.com/reports/1581454) -- Exodus | 7up
- [Host Header Injection and Cache Poisoning](https://hackerone.com/reports/277192) -- Inflection | 4up
- [Host Header Injection / Cache Poisoning](https://hackerone.com/reports/123513) -- New Relic | 3up
- [Host Header Injection or cache poisoning in multiple domains](https://hackerone.com/reports/283786) -- Inflection | 2up
- [Cache poisoning for okhttp](https://hackerone.com/reports/137756) -- Square Open Source | Violation of Secure Design Principles | 1up