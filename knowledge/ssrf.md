# SSRF -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Server Side Request Forgery (SSRF) via Analytics Reports](https://hackerone.com/reports/2262382) -- HackerOne | $25,000 | Server-Side Request Forgery (SSRF) | 528up
  > We recently received a critical server-side request forgery (SSRF) vulnerability report through our bug bounty program. The issue allowed attackers to make internal requests from our application servers by exploiting a lack of output sanitization in an error message. By crafting malicious requests, an attacker could have accessed internal AWS services and obtained temporary credentials.   Upon...
- [Full Response SSRF via Google Drive](https://hackerone.com/reports/1406938) -- Dropbox | $17,576 | Server-Side Request Forgery (SSRF) | 302up
- [SSRF on project import via the remote_attachment_url on a Note](https://hackerone.com/reports/826361) -- GitLab | $10,000 | Server-Side Request Forgery (SSRF) | 359up
  > ### Summary  The Note model has an `attachment` which is provided by a CarrierWave uploader:  ```ruby mount_uploader :attachment, AttachmentUploader ```  One of the features this provides is the ability to download and attach a file via a url, see https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb#L80. This means that the Note model has a method...
- [Blind SSRF to internal services in matrix preview_link API](https://hackerone.com/reports/1960765) -- Reddit | $6,000 | Server-Side Request Forgery (SSRF) | 344up
  > Matrix Chat endpoint at https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=* allowed partially blind SSRF to internal services. The data that could be exfiltrated was limited only to the service names and their IPs before a fix was implemented. This endpoint should not be able to query internal services, but external IPs, domains and services are fine for this to query.
- [Open Selenoid instance at 188.93.63.186 leads to LFR/SSRF.](https://hackerone.com/reports/512973) -- Mail.ru | $6,000 | Improper Access Control - Generic | 93up
- [Full read SSRF via Lark Docs `import as docs` feature](https://hackerone.com/reports/1409727) -- Lark Technologies | $5,000 | Server-Side Request Forgery (SSRF) | 124up
  > A SSRF (server side request forgery) vulnerability was found in the LarkDocs using the "import as docs" feature, which could have potentially been used to access services running on the internal network. We thank @sirleeroyjenkins for reporting this to our team and confirming the resolution.
- [[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia](https://hackerone.com/reports/1547877) -- Aiven Ltd | $5,000 | Unrestricted Upload of File with Dangerous Type | 56up
  > ## Summary: The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto the server. The HTTP sink connector allows sending HTTP requests to localhost. There is unprotected Jolokia listening on `localhost:6725`.  JMX exports the `com.sun.management:type=DiagnosticCommand` MBean, which contains the `jvmtiAgentLoad` operation. This...
- [Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.](https://hackerone.com/reports/776017) -- Kubernetes | $5,000 | Server-Side Request Forgery (SSRF) | 21up
  > Hello,  ## Who we are :  We’re two French security researchers and our respective names are Brice Augras and Christophe Hauquiert, we worked and found the vulnerability together.  Brice Augras from https://www.groupe-asten.fr/ company - https://hackerone.com/reeverzax Christophe Hauquiert - https://hackerone.com/hach  ## Summary  We recently led some security investigations about Kubernetes...
- [important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)](https://hackerone.com/reports/2585385) -- Internet Bug Bounty | $4,920 | Server-Side Request Forgery (SSRF) | 45up
  > ###important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)  SSRF in Apache HTTP Server on Windows allows to potentially leak NTML hashes to a malicious server via SSRF and malicious requests or content  Users are recommended to upgrade to version 2.4.60 which fixes this issue. Note: Existing configurations that access UNC paths will have to configure new directive "UNCList" to allow...
- [Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure](https://hackerone.com/reports/923132) -- Dropbox | $4,913 | Server-Side Request Forgery (SSRF) | 360up
- [Libuv: Improper Domain Lookup that potentially leads to SSRF attacks](https://hackerone.com/reports/2429894) -- Internet Bug Bounty | $4,860 | Server-Side Request Forgery (SSRF) | 74up
  > Improper Domain Lookup that potentially leads to SSRF attacks  Summary The uv_getaddrinfo function in src/unix/getaddrinfo.c (and its windows counterpart src/win/getaddrinfo.c), truncates hostnames to 256 characters before calling getaddrinfo. This behavior can be exploited to create addresses like 0x00007f000001, which are considered valid by getaddrinfo and could allow an attacker to craft...
- [SSRF on music.line.me through getXML.php](https://hackerone.com/reports/746024) -- LY Corporation | $4,500 | Server-Side Request Forgery (SSRF) | 135up
  > The reporter found an endpoint through which limited SSRF could be achieved. It was only possible to issue GET requests served over HTTPS. LFI was not possible. The maximum impact found for this issue was minor service disruption and/or limited information leakage.
- [important: Apache HTTP Server: SSRF with mod_rewrite in server/vhost context on Windows (CVE-2024-40898)](https://hackerone.com/reports/2612028) -- Internet Bug Bounty | $4,263 | 19up
  > important: Apache HTTP Server: SSRF with mod_rewrite in server/vhost context on Windows (CVE-2024-40898) SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context, allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests.  Users are recommended to upgrade to version 2.4.62 which fixes this issue.  Acknowledgements:  finder: Smi1e...
- [Unauthenticated blind SSRF in OAuth Jira authorization controller](https://hackerone.com/reports/398799) -- GitLab | $4,000 | Server-Side Request Forgery (SSRF) | 238up
  > The `Oauth::Jira::AuthorizationsController#access_token` endpoint is vulnerable to a blind SSRF vulnerability. The vulnerability allows an attacker to make arbitrary HTTP/HTTPS requests inside a GitLab instance's network.  # Proof of concept To reproduce the vulnerability, follow the steps below.   - spin up a GitLab EE instance with the latest version (11.2.1-ee)  - send a `POST` request to...
- [SSRF via Office file thumbnails](https://hackerone.com/reports/671935) -- Slack | $4,000 | Information Disclosure | 107up
  > On August 12, 2019, a group of researchers reported an exploit path for a vulnerability in LibreOffice. Slack uses LibreOffice to process certain file types for preview. A specially crafted file uploaded to Slack could permit local file access and expose an internal Slack AWS credential for the container used to process these files. This was categorized as Critical, in our internal rubric,...

---

- [SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]](https://hackerone.com/reports/1628209) -- U.S. Dept Of Defense | $4,000 | Server-Side Request Forgery (SSRF) | 46up
- [TURN server allows TCP and UDP proxying to internal network, localhost and meta-data services](https://hackerone.com/reports/333419) -- Slack | $3,500 | Server-Side Request Forgery (SSRF) | 323up
- [Blind SSRF on errors.hackerone.net due to Sentry misconfiguration](https://hackerone.com/reports/374737) -- HackerOne | $3,500 | Server-Side Request Forgery (SSRF) | 143up
- [SSRF in graphQL query (pwapi.ex2b.com)](https://hackerone.com/reports/1864188) -- EXNESS | $3,000 | Server-Side Request Forgery (SSRF) | 261up
- [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049) -- Lark Technologies | $3,000 | Server-Side Request Forgery (SSRF) | 178up
- [Injection of `http.<url>.*` git config settings leading to SSRF](https://hackerone.com/reports/855276) -- GitLab | $3,000 | Server-Side Request Forgery (SSRF) | 36up
- [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) -- TikTok | $2,727 | Server-Side Request Forgery (SSRF) | 162up
- [Server Side Request Forgery (SSRF) in webhook functionality](https://hackerone.com/reports/2301565) -- HackerOne | $2,500 | Server-Side Request Forgery (SSRF) | 139up
- [Blind SSRF in horizon-heat](https://hackerone.com/reports/893856) -- Mail.ru | $2,500 | Server-Side Request Forgery (SSRF) | 91up
- [Blind SSRF in magnum upgrade_params](https://hackerone.com/reports/907819) -- Mail.ru | $2,500 | Server-Side Request Forgery (SSRF) | 54up
- [MCS Graphite SSRF: internal network access](https://hackerone.com/reports/818109) -- Mail.ru | $2,500 | Server-Side Request Forgery (SSRF) | 34up
- [[SSRF] Server-Side Request Forgery at https://sea-web.gold.razer.com/dev/simulator via notify_url Parameter](https://hackerone.com/reports/777664) -- Razer | $2,000 | Server-Side Request Forgery (SSRF) | 60up
- [Full read SSRF in flyte-poc-us-east4.uberinternal.com](https://hackerone.com/reports/1540906) -- Uber | $2,000 | Server-Side Request Forgery (SSRF) | 30up
- [GitLab's GitHub integration is vulnerable to SSRF vulnerability](https://hackerone.com/reports/446593) -- GitLab | $2,000 | Server-Side Request Forgery (SSRF) | 29up
- [SSRF in clients.city-mobil.ru](https://hackerone.com/reports/712103) -- Mail.ru | $1,500 | Server-Side Request Forgery (SSRF) | 132up
- [Blind SSRF in emblem editor (2)](https://hackerone.com/reports/265050) -- Rockstar Games | $1,500 | Server-Side Request Forgery (SSRF) | 82up
- [LFI and SSRF via XXE in emblem editor](https://hackerone.com/reports/347139) -- Rockstar Games | $1,500 | XML External Entities (XXE) | 79up
- [SMB SSRF in emblem editor exposes taketwo domain credentials, may lead to RCE](https://hackerone.com/reports/288353) -- Rockstar Games | $1,500 | Server-Side Request Forgery (SSRF) | 52up
- [SSRF - Unchecked Snippet IDs for distributed files](https://hackerone.com/reports/997926) -- Open-Xchange | $1,500 | Server-Side Request Forgery (SSRF) | 49up
- [[ssrf] libav vulnerable during conversion of uploaded videos](https://hackerone.com/reports/111269) -- Pornhub | $1,500 | Information Disclosure | 10up
- [Get-based SSRF limited to HTTP protocol on https://resizer.line-apps.com/form](https://hackerone.com/reports/707014) -- LY Corporation | $1,350 | Server-Side Request Forgery (SSRF) | 56up
- [SSRF chained to hit internal host leading to another SSRF which allows to read internal images.](https://hackerone.com/reports/826097) -- PlayStation | $1,000 | Server-Side Request Forgery (SSRF) | 148up
- [SSRF on image renderer](https://hackerone.com/reports/811136) -- PlayStation | $1,000 | 103up
- [Reverse Proxy misroute leading to steal X-Shopify-Access-Token header](https://hackerone.com/reports/429617) -- Shopify | $1,000 | Server-Side Request Forgery (SSRF) | 89up
- [mail.acronis.com is vulnerable to zero day vulnerability CVE-2022-41040](https://hackerone.com/reports/1719719) -- Acronis | $1,000 | Server-Side Request Forgery (SSRF) | 71up
- [Inappropriate URL parsing may cause security risk!](https://hackerone.com/reports/305974) -- Internet Bug Bounty | $1,000 | Server-Side Request Forgery (SSRF) | 58up
- [SSRF to read AWS metaData at https://█████/ [HtUS]](https://hackerone.com/reports/1624140) -- U.S. Dept Of Defense | $1,000 | Server-Side Request Forgery (SSRF) | 56up
- [SSRF vulnerability can be exploited when a hijacked aggregated api server such as metrics-server returns 30X](https://hackerone.com/reports/1544133) -- Kubernetes | $1,000 | Server-Side Request Forgery (SSRF) | 51up
- [CreatorID leaked from public content posted to SnapMaps](https://hackerone.com/reports/867521) -- Snapchat | $1,000 | Server-Side Request Forgery (SSRF) | 49up
- [Blind SSRF on [relap.io]](https://hackerone.com/reports/785384) -- Mail.ru | $1,000 | Server-Side Request Forgery (SSRF) | 33up
- [SSRF & XSS (W3 Total Cache)](https://hackerone.com/reports/138721) -- Pornhub | $1,000 | Cross-site Scripting (XSS) - Generic | 7up
- [SSRF in VCARD photo upload functionality](https://hackerone.com/reports/296045) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 49up
- [SSRF - RSS feed, blacklist bypass (301 re-direct)](https://hackerone.com/reports/299135) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 33up
- [SSRF - RSS feed, blacklist bypass (IP Formatting)](https://hackerone.com/reports/299130) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 32up
- [SSRF in /appsuite/api/autoconfig](https://hackerone.com/reports/293847) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 20up
- [Unchecked URL in attachment datasource](https://hackerone.com/reports/725307) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 15up
- [[SSRF] PDF documentconverterws](https://hackerone.com/reports/361793) -- Open-Xchange | $850 | Server-Side Request Forgery (SSRF) | 10up
- [SSRF на https://target.my.com/](https://hackerone.com/reports/200224) -- Mail.ru | $800 | Server-Side Request Forgery (SSRF) | 14up
- [Attacker can send requests from mail.ru server](https://hackerone.com/reports/347850) -- Mail.ru | $800 | Server-Side Request Forgery (SSRF) | 13up
- [Чтение файлов на сервере и раскрытие директорий mediator.media](https://hackerone.com/reports/411466) -- Mail.ru | $800 | Server-Side Request Forgery (SSRF) | 6up
- [[tanks.mail.ru] SSRF + Кража cookie](https://hackerone.com/reports/1166943) -- Mail.ru | $750 | Cross-Site Request Forgery (CSRF) | 55up
- [Evaluating Ruby code by injecting Rescue job on the system_hook_push queue through web hook](https://hackerone.com/reports/299473) -- GitLab | $750 | Server-Side Request Forgery (SSRF) | 35up
- [Unsecured Kibana/Elasticsearch instance](https://hackerone.com/reports/188482) -- Pornhub | $750 | Server-Side Request Forgery (SSRF) | 18up
- [[la.mail.ru] - SSRF + кража cookie](https://hackerone.com/reports/1166977) -- Mail.ru | $750 | 16up
- [SSRF allows access to internal services like Ganglia](https://hackerone.com/reports/151086) -- Dropbox | $729 | Information Disclosure | 14up
- [Open TURN relay abuse is possible due to lack of peer access control (Critical)](https://hackerone.com/reports/843256) -- 8x8 | $700 | Server-Side Request Forgery (SSRF) | 23up
- [SSRF protection bypass in /appsuite/api/oxodocumentfilter addfile action](https://hackerone.com/reports/863553) -- Open-Xchange | $550 | Server-Side Request Forgery (SSRF) | 12up
- [Blind SSRF in /appsuite/api/oxodocumentfilter&action=addfile](https://hackerone.com/reports/865652) -- Open-Xchange | $550 | Server-Side Request Forgery (SSRF) | 10up
- [SSRF vulnerablity in app webhooks](https://hackerone.com/reports/56828) -- Dropbox | $512 | Information Disclosure | 9up
- [SVG Server Side Request Forgery (SSRF)](https://hackerone.com/reports/223203) -- Shopify | $500 | Server-Side Request Forgery (SSRF) | 81up
- [SSRF with bypass leads to client side hosting / vulnerabilities ( XSS and others )](https://hackerone.com/reports/3522157) -- DuckDuckGo | $500 | Server-Side Request Forgery (SSRF) | 74up
- [SSRF and local file disclosure by video upload on https://www.redtube.com/upload](https://hackerone.com/reports/570537) -- Pornhub | $500 | Server-Side Request Forgery (SSRF) | 61up
- [SSRF in hatchful.shopify.com](https://hackerone.com/reports/409701) -- Shopify | $500 | Server-Side Request Forgery (SSRF) | 56up
- [SSRF and local file disclosure by video upload on https://www.tube8.com/](https://hackerone.com/reports/574133) -- Pornhub | $500 | Server-Side Request Forgery (SSRF) | 53up
- [SSRF - Blacklist bypass for mail account addition](https://hackerone.com/reports/303378) -- Open-Xchange | $500 | Server-Side Request Forgery (SSRF) | 43up
- [[data-07.uberinternal.com] SSRF in Portainer app lead to access to Internal Docker API without Auth](https://hackerone.com/reports/366638) -- Uber | $500 | Server-Side Request Forgery (SSRF) | 37up
- [SSRF and local file disclosure by video upload on http://www.youporn.com/](https://hackerone.com/reports/574134) -- Pornhub | $500 | Server-Side Request Forgery (SSRF) | 35up
- [Host header injection that bypassed protection and allowed accessing multiple subdomains](https://hackerone.com/reports/1783015) -- Urban Company | $500 | Server-Side Request Forgery (SSRF) | 33up
- [SSRF when configuring Website Backup on Acronis Cloud](https://hackerone.com/reports/1072873) -- Acronis | $500 | Server-Side Request Forgery (SSRF) | 30up
- [Lack of input sanitization in Marketo form leads to execution of HTML in lead emails](https://hackerone.com/reports/220009) -- HackerOne | $500 | Server-Side Request Forgery (SSRF) | 25up
- [Blind SSRF on sentry.dev-my.com due to Sentry misconfiguration](https://hackerone.com/reports/686363) -- Mail.ru | $500 | Server-Side Request Forgery (SSRF) | 17up
- [cURL / libcURL - CVE-2016-8624 invalid URL parsing with '#'](https://hackerone.com/reports/180434) -- Internet Bug Bounty | $500 | Server-Side Request Forgery (SSRF) | 10up
- [Urllib connects to a wrong host](https://hackerone.com/reports/305978) -- Internet Bug Bounty | $500 | Server-Side Request Forgery (SSRF) | 6up
- [CodeQL query to detect SSRF in Python](https://hackerone.com/reports/872094) -- GitHub Security Lab | $500 | 1up
- [SSRF - Office Documents - Image URL](https://hackerone.com/reports/738015) -- Open-Xchange | $450 | Server-Side Request Forgery (SSRF) | 37up
- [Yet another SSRF query for Go](https://hackerone.com/reports/1391729) -- GitHub Security Lab | $450 | 4up
- [Yet another SSRF query for Go](https://hackerone.com/reports/1391771) -- GitHub Security Lab | $450 | 4up
- [SSRF - Image Sources in HTML Snippets - 727234 bypass](https://hackerone.com/reports/737163) -- Open-Xchange | $400 | Server-Side Request Forgery (SSRF) | 41up
- [SSRF - URL Attachments - 725307 bypass](https://hackerone.com/reports/737161) -- Open-Xchange | $400 | Server-Side Request Forgery (SSRF) | 37up
- [SSRF - Guard - Unchecked WKS servers](https://hackerone.com/reports/792960) -- Open-Xchange | $400 | Server-Side Request Forgery (SSRF) | 4up
- [SSRF - Guard - Unchecked HKP servers](https://hackerone.com/reports/792953) -- Open-Xchange | $400 | Server-Side Request Forgery (SSRF) | 4up
- [Blind SSRF on https://labs.data.gov/dashboard/Campaign/json_status/ Endpoint](https://hackerone.com/reports/895696) -- GSA Bounty | $300 | Use of Inherently Dangerous Function | 61up
- [SSRF/XSPA in labs.data.gov/dashboard/validate](https://hackerone.com/reports/272095) -- GSA Bounty | $300 | Server-Side Request Forgery (SSRF) | 41up
- [SSRF in notifications.server configuration](https://hackerone.com/reports/850114) -- Phabricator | $300 | Server-Side Request Forgery (SSRF) | 28up
- [Potential SSRF in sales.mail.ru](https://hackerone.com/reports/97395) -- Mail.ru | $300 | Server-Side Request Forgery (SSRF) | 15up
- [SSRF через Share-ботов](https://hackerone.com/reports/197365) -- VK.com | $300 | Server-Side Request Forgery (SSRF) | 4up
- [connect.mail.ru: SSRF](https://hackerone.com/reports/14033) -- Mail.ru | $300 | 4up
- [SSRF vulnerability (access to metadata server on EC2 and OpenStack)](https://hackerone.com/reports/53088) -- Phabricator | $300 | Information Disclosure | 4up
- [SSRF in the application's image export functionality](https://hackerone.com/reports/816848) -- Visma Public | $250 | Server-Side Request Forgery (SSRF) | 42up
- [SSRF via filter bypass due to lax checking on IPs](https://hackerone.com/reports/1702864) -- Nextcloud | $250 | Server-Side Request Forgery (SSRF) | 33up
- [SSRF via potential filter bypass with too lax local domain checking](https://hackerone.com/reports/1608039) -- Nextcloud | $250 | Server-Side Request Forgery (SSRF) | 30up
- [Unauthenticated SSRF in 3rd party module "cerdic/csstidy"](https://hackerone.com/reports/1595006) -- Nextcloud | $250 | Server-Side Request Forgery (SSRF) | 17up
- [Yet another SSRF query for Javascript](https://hackerone.com/reports/1391727) -- GitHub Security Lab | $250 | 4up
- [Yet another SSRF query for Javascript](https://hackerone.com/reports/1391726) -- GitHub Security Lab | $250 | 3up
- [Java: CWE-918 - Server Side Request Forgery (SSRF)](https://hackerone.com/reports/1008846) -- GitHub Security Lab | $250 | 1up