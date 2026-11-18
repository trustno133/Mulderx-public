# CSRF -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Server Side Request Forgery (SSRF) via Analytics Reports](https://hackerone.com/reports/2262382) -- HackerOne | $25,000 | Server-Side Request Forgery (SSRF) | 528up
  > We recently received a critical server-side request forgery (SSRF) vulnerability report through our bug bounty program. The issue allowed attackers to make internal requests from our application servers by exploiting a lack of output sanitization in an error message. By crafting malicious requests, an attacker could have accessed internal AWS services and obtained temporary credentials.   Upon...
- [Full Response SSRF via Google Drive](https://hackerone.com/reports/1406938) -- Dropbox | $17,576 | Server-Side Request Forgery (SSRF) | 302up
- [SSRF on project import via the remote_attachment_url on a Note](https://hackerone.com/reports/826361) -- GitLab | $10,000 | Server-Side Request Forgery (SSRF) | 359up
  > ### Summary  The Note model has an `attachment` which is provided by a CarrierWave uploader:  ```ruby mount_uploader :attachment, AttachmentUploader ```  One of the features this provides is the ability to download and attach a file via a url, see https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb#L80. This means that the Note model has a method...
- [CSRF protection bypass in GitHub Enterprise management console](https://hackerone.com/reports/1497169) -- GitHub | $10,000 | Cross-Site Request Forgery (CSRF) | 151up
  > A path traversal vulnerability was identified in GitHub Enterprise Server management console that allowed the bypass of CSRF protections. This could potentially lead to privilege escalation. To exploit this vulnerability, an attacker would need to target a user that was actively logged into the management console. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.5...
- [Blind SSRF to internal services in matrix preview_link API](https://hackerone.com/reports/1960765) -- Reddit | $6,000 | Server-Side Request Forgery (SSRF) | 344up
  > Matrix Chat endpoint at https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=* allowed partially blind SSRF to internal services. The data that could be exfiltrated was limited only to the service names and their IPs before a fix was implemented. This endpoint should not be able to query internal services, but external IPs, domains and services are fine for this to query.
- [Full read SSRF via Lark Docs `import as docs` feature](https://hackerone.com/reports/1409727) -- Lark Technologies | $5,000 | Server-Side Request Forgery (SSRF) | 124up
  > A SSRF (server side request forgery) vulnerability was found in the LarkDocs using the "import as docs" feature, which could have potentially been used to access services running on the internal network. We thank @sirleeroyjenkins for reporting this to our team and confirming the resolution.
- [Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.](https://hackerone.com/reports/776017) -- Kubernetes | $5,000 | Server-Side Request Forgery (SSRF) | 21up
  > Hello,  ## Who we are :  We’re two French security researchers and our respective names are Brice Augras and Christophe Hauquiert, we worked and found the vulnerability together.  Brice Augras from https://www.groupe-asten.fr/ company - https://hackerone.com/reeverzax Christophe Hauquiert - https://hackerone.com/hach  ## Summary  We recently led some security investigations about Kubernetes...
- [important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)](https://hackerone.com/reports/2585385) -- Internet Bug Bounty | $4,920 | Server-Side Request Forgery (SSRF) | 45up
  > ###important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)  SSRF in Apache HTTP Server on Windows allows to potentially leak NTML hashes to a malicious server via SSRF and malicious requests or content  Users are recommended to upgrade to version 2.4.60 which fixes this issue. Note: Existing configurations that access UNC paths will have to configure new directive "UNCList" to allow...
- [Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure](https://hackerone.com/reports/923132) -- Dropbox | $4,913 | Server-Side Request Forgery (SSRF) | 360up
- [Libuv: Improper Domain Lookup that potentially leads to SSRF attacks](https://hackerone.com/reports/2429894) -- Internet Bug Bounty | $4,860 | Server-Side Request Forgery (SSRF) | 74up
  > Improper Domain Lookup that potentially leads to SSRF attacks  Summary The uv_getaddrinfo function in src/unix/getaddrinfo.c (and its windows counterpart src/win/getaddrinfo.c), truncates hostnames to 256 characters before calling getaddrinfo. This behavior can be exploited to create addresses like 0x00007f000001, which are considered valid by getaddrinfo and could allow an attacker to craft...
- [Argo CD CSRF leads to Kubernetes cluster compromise](https://hackerone.com/reports/2326194) -- Internet Bug Bounty | $4,660 | Cross-Site Request Forgery (CSRF) | 34up
  > Cross-Site Request Forgery (CSRF) in github.com/argoproj/argo-cd  CVE-2024-22424 Severity: High  Impact The Argo CD API prior to versions 2.10-rc2, 2.9.4, 2.8.8, and 2.7.16 are vulnerable to a cross-server request forgery (CSRF) attack when the attacker has the ability to write HTML to a page on the same parent domain as Argo CD.  A CSRF attack works by tricking an authenticated Argo CD user...
- [SSRF on music.line.me through getXML.php](https://hackerone.com/reports/746024) -- LY Corporation | $4,500 | Server-Side Request Forgery (SSRF) | 135up
  > The reporter found an endpoint through which limited SSRF could be achieved. It was only possible to issue GET requests served over HTTPS. LFI was not possible. The maximum impact found for this issue was minor service disruption and/or limited information leakage.
- [Unauthenticated blind SSRF in OAuth Jira authorization controller](https://hackerone.com/reports/398799) -- GitLab | $4,000 | Server-Side Request Forgery (SSRF) | 238up
  > The `Oauth::Jira::AuthorizationsController#access_token` endpoint is vulnerable to a blind SSRF vulnerability. The vulnerability allows an attacker to make arbitrary HTTP/HTTPS requests inside a GitLab instance's network.  # Proof of concept To reproduce the vulnerability, follow the steps below.   - spin up a GitLab EE instance with the latest version (11.2.1-ee)  - send a `POST` request to...
- [SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]](https://hackerone.com/reports/1628209) -- U.S. Dept Of Defense | $4,000 | Server-Side Request Forgery (SSRF) | 46up
  > ## Summary: I found that it is possible to inject a javascript payload during the PDF form creation process, which is then executed by the checklist application server.  ## Vulnerable Software: Functional Administrative Support Tool (FAST) v1.0  ## Intro:   ██████████  Administrative clerks create a dynamic action items by guiding a███ through targeted questions designed to draw out required...
- [TURN server allows TCP and UDP proxying to internal network, localhost and meta-data services](https://hackerone.com/reports/333419) -- Slack | $3,500 | Server-Side Request Forgery (SSRF) | 323up
  > TURN server allowed proxying of TCP connections and UDP packets to internal Slack network and meta-data services on AWS.

---

- [Blind SSRF on errors.hackerone.net due to Sentry misconfiguration](https://hackerone.com/reports/374737) -- HackerOne | $3,500 | Server-Side Request Forgery (SSRF) | 143up
- [XSSI on refer.xoom.com allows stealing email addresses and posting to Twitter on behalf of victim](https://hackerone.com/reports/450796) -- PayPal | $3,500 | Cross-Site Request Forgery (CSRF) | 81up
- [CSRF on /api/graphql allows executing mutations through GET requests](https://hackerone.com/reports/1122408) -- GitLab | $3,370 | Cross-Site Request Forgery (CSRF) | 87up
- [SSRF in graphQL query (pwapi.ex2b.com)](https://hackerone.com/reports/1864188) -- EXNESS | $3,000 | Server-Side Request Forgery (SSRF) | 261up
- [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049) -- Lark Technologies | $3,000 | Server-Side Request Forgery (SSRF) | 178up
- [Injection of `http.<url>.*` git config settings leading to SSRF](https://hackerone.com/reports/855276) -- GitLab | $3,000 | Server-Side Request Forgery (SSRF) | 36up
- [Periscope iOS app CSRF in follow action due to deeplink](https://hackerone.com/reports/805073) -- X / xAI | $2,940 | Cross-Site Request Forgery (CSRF) | 58up
- [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) -- TikTok | $2,727 | Server-Side Request Forgery (SSRF) | 162up
- [Slack integration setup lacks CSRF protection](https://hackerone.com/reports/170552) -- HackerOne | $2,500 | Cross-Site Request Forgery (CSRF) | 149up
- [Server Side Request Forgery (SSRF) in webhook functionality](https://hackerone.com/reports/2301565) -- HackerOne | $2,500 | Server-Side Request Forgery (SSRF) | 139up
- [Blind SSRF in horizon-heat](https://hackerone.com/reports/893856) -- Mail.ru | $2,500 | Server-Side Request Forgery (SSRF) | 91up
- [CSRF token validation system is disabled on Stripe Dashboard](https://hackerone.com/reports/1493437) -- Stripe | $2,500 | Cross-Site Request Forgery (CSRF) | 86up
- [CSRF protection bypass on TikTok Webcast Endpoints](https://hackerone.com/reports/1543234) -- TikTok | $2,500 | Cross-Site Request Forgery (CSRF) | 79up
- [Blind SSRF in magnum upgrade_params](https://hackerone.com/reports/907819) -- Mail.ru | $2,500 | Server-Side Request Forgery (SSRF) | 54up
- [MCS Graphite SSRF: internal network access](https://hackerone.com/reports/818109) -- Mail.ru | $2,500 | Server-Side Request Forgery (SSRF) | 34up
- [CSRF possible when SOP Bypass/UXSS is available](https://hackerone.com/reports/103787) -- HackerOne | $2,500 | Cross-Site Request Forgery (CSRF) | 11up
- [Account takeover due to insufficient URL validation on RelayState parameter](https://hackerone.com/reports/1923672) -- GitLab | $2,450 | Cross-Site Request Forgery (CSRF) | 98up
- [[SSRF] Server-Side Request Forgery at https://sea-web.gold.razer.com/dev/simulator via notify_url Parameter](https://hackerone.com/reports/777664) -- Razer | $2,000 | Server-Side Request Forgery (SSRF) | 60up
- [[uchat.uberinternals.com] Mattermost doesn't check Origin in Websockets, which leads to the Critical Inforamation Leakage.](https://hackerone.com/reports/201326) -- Uber | $2,000 | Cross-Site Request Forgery (CSRF) | 50up
- [Full read SSRF in flyte-poc-us-east4.uberinternal.com](https://hackerone.com/reports/1540906) -- Uber | $2,000 | Server-Side Request Forgery (SSRF) | 30up
- [GitLab's GitHub integration is vulnerable to SSRF vulnerability](https://hackerone.com/reports/446593) -- GitLab | $2,000 | Server-Side Request Forgery (SSRF) | 29up
- [CSP Bypass: Click handler for links with data-method="post" can cause authenticity_token to be sent off domain](https://hackerone.com/reports/47472) -- HackerOne | $2,000 | Cross-Site Request Forgery (CSRF) | 10up
- [authenticity token not verfied leads to change business name](https://hackerone.com/reports/994504) -- Shopify | $1,900 | Cross-Site Request Forgery (CSRF) | 54up
- [CodeQL query for finding CSRF vulnerabilities in Spring applications](https://hackerone.com/reports/785120) -- GitHub Security Lab | $1,800 | 4up
- [Exfiltrate GDrive access token using CSRF](https://hackerone.com/reports/1468010) -- Dropbox | $1,728 | Information Disclosure | 32up
- [Periscope android app deeplink leads to CSRF in follow action](https://hackerone.com/reports/583987) -- X / xAI | $1,540 | Cross-Site Request Forgery (CSRF) | 224up
- [SSRF in clients.city-mobil.ru](https://hackerone.com/reports/712103) -- Mail.ru | $1,500 | Server-Side Request Forgery (SSRF) | 132up
- [Blind SSRF in emblem editor (2)](https://hackerone.com/reports/265050) -- Rockstar Games | $1,500 | Server-Side Request Forgery (SSRF) | 82up
- [SMB SSRF in emblem editor exposes taketwo domain credentials, may lead to RCE](https://hackerone.com/reports/288353) -- Rockstar Games | $1,500 | Server-Side Request Forgery (SSRF) | 52up
- [SSRF - Unchecked Snippet IDs for distributed files](https://hackerone.com/reports/997926) -- Open-Xchange | $1,500 | Server-Side Request Forgery (SSRF) | 49up
- [Get-based SSRF limited to HTTP protocol on https://resizer.line-apps.com/form](https://hackerone.com/reports/707014) -- LY Corporation | $1,350 | Server-Side Request Forgery (SSRF) | 56up
- [SQL Injection on /webApp/sijoitustalousuk email-parameter + potential lack of CSRF Token (viestinta.lahitapiola.fi)](https://hackerone.com/reports/191601) -- LocalTapiola | $1,350 | SQL Injection | 18up
- [Chaining Bugs: Leakage of CSRF token which leads to Stored XSS and Account Takeover (xs1.tribalwars.cash)](https://hackerone.com/reports/604120) -- InnoGames | $1,100 | Insecure Storage of Sensitive Information | 186up
- [SSRF chained to hit internal host leading to another SSRF which allows to read internal images.](https://hackerone.com/reports/826097) -- PlayStation | $1,000 | Server-Side Request Forgery (SSRF) | 148up
- [Reverse Proxy misroute leading to steal X-Shopify-Access-Token header](https://hackerone.com/reports/429617) -- Shopify | $1,000 | Server-Side Request Forgery (SSRF) | 89up
- [mail.acronis.com is vulnerable to zero day vulnerability CVE-2022-41040](https://hackerone.com/reports/1719719) -- Acronis | $1,000 | Server-Side Request Forgery (SSRF) | 71up
- [Inappropriate URL parsing may cause security risk!](https://hackerone.com/reports/305974) -- Internet Bug Bounty | $1,000 | Server-Side Request Forgery (SSRF) | 58up
- [SSRF to read AWS metaData at https://█████/ [HtUS]](https://hackerone.com/reports/1624140) -- U.S. Dept Of Defense | $1,000 | Server-Side Request Forgery (SSRF) | 56up
- [SSRF vulnerability can be exploited when a hijacked aggregated api server such as metrics-server returns 30X](https://hackerone.com/reports/1544133) -- Kubernetes | $1,000 | Server-Side Request Forgery (SSRF) | 51up
- [CreatorID leaked from public content posted to SnapMaps](https://hackerone.com/reports/867521) -- Snapchat | $1,000 | Server-Side Request Forgery (SSRF) | 49up
- [Blind SSRF on [relap.io]](https://hackerone.com/reports/785384) -- Mail.ru | $1,000 | Server-Side Request Forgery (SSRF) | 33up
- [CSRF on TikTok Ads Portal](https://hackerone.com/reports/1087436) -- TikTok | $1,000 | Cross-Site Request Forgery (CSRF) | 23up
- [Chained vulnerabilities create DOS attack against users on desafio5estrelas.com](https://hackerone.com/reports/624645) -- Uber | $1,000 | Cross-Site Request Forgery (CSRF) | 17up
- [Leaking CSRF token over HTTP resulting in CSRF protection bypass](https://hackerone.com/reports/15412) -- Coinbase | $1,000 | Cross-Site Request Forgery (CSRF) | 6up
- [SSRF in VCARD photo upload functionality](https://hackerone.com/reports/296045) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 49up
- [SSRF - RSS feed, blacklist bypass (301 re-direct)](https://hackerone.com/reports/299135) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 33up
- [SSRF - RSS feed, blacklist bypass (IP Formatting)](https://hackerone.com/reports/299130) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 32up
- [SSRF in /appsuite/api/autoconfig](https://hackerone.com/reports/293847) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 20up
- [Unchecked URL in attachment datasource](https://hackerone.com/reports/725307) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 15up
- [[SSRF] PDF documentconverterws](https://hackerone.com/reports/361793) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 10up
- [Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage](https://hackerone.com/reports/1271944) -- Shopify | $800 | Violation of Secure Design Principles | 48up
- [SSRF на https://target.my.com/](https://hackerone.com/reports/200224) -- Mail.ru | $800 | Server-Side Request Forgery (SSRF) | 14up
- [Attacker can send requests from mail.ru server](https://hackerone.com/reports/347850) -- Mail.ru | $800 | Server-Side Request Forgery (SSRF) | 13up
- [Чтение файлов на сервере и раскрытие директорий mediator.media](https://hackerone.com/reports/411466) -- Mail.ru | $800 | Server-Side Request Forgery (SSRF) | 6up
- [[tanks.mail.ru] SSRF + Кража cookie](https://hackerone.com/reports/1166943) -- Mail.ru | $750 | Cross-Site Request Forgery (CSRF) | 55up
- [Evaluating Ruby code by injecting Rescue job on the system_hook_push queue through web hook](https://hackerone.com/reports/299473) -- GitLab | $750 | Server-Side Request Forgery (SSRF) | 35up
- [Drive-by arbitrary file deletion in the GDK via letter_opener_web gem](https://hackerone.com/reports/1353103) -- GitLab | $750 | Cross-Site Request Forgery (CSRF) | 27up
- [Unsecured Kibana/Elasticsearch instance](https://hackerone.com/reports/188482) -- Pornhub | $750 | Server-Side Request Forgery (SSRF) | 18up
- [[XSS/CSRF] filter content-type bypass in Files](https://hackerone.com/reports/304098) -- Open-Xchange | $750 | Cross-site Scripting (XSS) - Stored | 10up
- [Open TURN relay abuse is possible due to lack of peer access control (Critical)](https://hackerone.com/reports/843256) -- 8x8 | $700 | Server-Side Request Forgery (SSRF) | 23up
- [PUT Based CSRF via Client Side Path Traversal + Cookie Bomb on Acronis Cloud](https://hackerone.com/reports/1860380) -- Acronis | $600 | Path Traversal | 76up
- [Same Origin Policy bypass](https://hackerone.com/reports/47495) -- Mail.ru | $600 | Cross-Site Request Forgery (CSRF) | 5up
- [URGENT : NICHE.co Account Take Over Vulnerability](https://hackerone.com/reports/100849) -- X / xAI | $560 | Cross-Site Request Forgery (CSRF) | 7up
- [SSRF protection bypass in /appsuite/api/oxodocumentfilter addfile action](https://hackerone.com/reports/863553) -- Open-Xchange | $550 | Server-Side Request Forgery (SSRF) | 12up
- [Blind SSRF in /appsuite/api/oxodocumentfilter&action=addfile](https://hackerone.com/reports/865652) -- Open-Xchange | $550 | Server-Side Request Forgery (SSRF) | 10up
- [Login CSRF vulnerability on hackerone.com](https://hackerone.com/reports/834366) -- HackerOne | $500 | Cross-Site Request Forgery (CSRF) | 83up
- [SVG Server Side Request Forgery (SSRF)](https://hackerone.com/reports/223203) -- Shopify | $500 | Server-Side Request Forgery (SSRF) | 81up
- [CSRF protection on OIDC login is broken](https://hackerone.com/reports/1878381) -- Nextcloud | $500 | Cross-Site Request Forgery (CSRF) | 77up
- [SSRF with bypass leads to client side hosting / vulnerabilities ( XSS and others )](https://hackerone.com/reports/3522157) -- DuckDuckGo | $500 | Server-Side Request Forgery (SSRF) | 74up
- [csrftoken not unique to session or specific user and csrfmiddlewaretoken  can be altered](https://hackerone.com/reports/2513333) -- Mozilla | $500 | Cross-Site Request Forgery (CSRF) | 63up
- [SSRF and local file disclosure by video upload on https://www.redtube.com/upload](https://hackerone.com/reports/570537) -- Pornhub | $500 | Server-Side Request Forgery (SSRF) | 61up
- [SSRF in hatchful.shopify.com](https://hackerone.com/reports/409701) -- Shopify | $500 | Server-Side Request Forgery (SSRF) | 56up
- [SSRF and local file disclosure by video upload on https://www.tube8.com/](https://hackerone.com/reports/574133) -- Pornhub | $500 | Server-Side Request Forgery (SSRF) | 53up
- [CSRF combined with IDOR within Document Converter exposes files](https://hackerone.com/reports/398316) -- Open-Xchange | $500 | Cross-Site Request Forgery (CSRF) | 52up
- [SSRF - Blacklist bypass for mail account addition](https://hackerone.com/reports/303378) -- Open-Xchange | $500 | Server-Side Request Forgery (SSRF) | 43up
- [[data-07.uberinternal.com] SSRF in Portainer app lead to access to Internal Docker API without Auth](https://hackerone.com/reports/366638) -- Uber | $500 | Server-Side Request Forgery (SSRF) | 37up
- [CSRF in Changing User Verification Email](https://hackerone.com/reports/1531235) -- TikTok | $500 | Cross-Site Request Forgery (CSRF) | 37up
- [HackerOne reports escalation to JIRA is CSRF vulnerable](https://hackerone.com/reports/226418) -- HackerOne | $500 | Cross-Site Request Forgery (CSRF) | 36up
- [SSRF and local file disclosure by video upload on http://www.youporn.com/](https://hackerone.com/reports/574134) -- Pornhub | $500 | Server-Side Request Forgery (SSRF) | 35up
- [Host header injection that bypassed protection and allowed accessing multiple subdomains](https://hackerone.com/reports/1783015) -- Urban Company | $500 | Server-Side Request Forgery (SSRF) | 33up
- [CSRF at https://chatstory.pixiv.net/imported](https://hackerone.com/reports/534908) -- pixiv | $500 | Cross-Site Request Forgery (CSRF) | 31up
- [SSRF when configuring Website Backup on Acronis Cloud](https://hackerone.com/reports/1072873) -- Acronis | $500 | Server-Side Request Forgery (SSRF) | 30up
- [Outdated Wordpress installation and plugins at www.uberxgermany.com create CSRF and XSS vulnerabilities](https://hackerone.com/reports/323899) -- Uber | $500 | Cross-Site Request Forgery (CSRF) | 29up
- [Lack of input sanitization in Marketo form leads to execution of HTML in lead emails](https://hackerone.com/reports/220009) -- HackerOne | $500 | Server-Side Request Forgery (SSRF) | 25up
- [CSRF in github integration](https://hackerone.com/reports/174328) -- Slack | $500 | Cross-Site Request Forgery (CSRF) | 22up