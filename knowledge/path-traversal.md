# Path Traversal -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Arbitrary file read  via the bulk imports UploadsPipeline](https://hackerone.com/reports/1439593) -- GitLab | $29,000 | Path Traversal | 329up
  > ### Summary  The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be read and uploaded when importing a group.  When a group has uploads (such as markdown attachments), an `uploads.tar.gz` file will be downloaded and extracted in the...
- [Arbitrary file read via the UploadsRewriter when moving and issue](https://hackerone.com/reports/827052) -- GitLab | $20,000 | Path Traversal | 1503up
  > ### Summary The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project.  The pattern used to look for references is : ```   MARKDOWN_PATTERN = %r{\!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}.freeze ```  This is used by the `UploadsRewriter` when copying an issue to also copy across...
- [Arbitrary file read during project import](https://hackerone.com/reports/1132378) -- GitLab | $16,000 | Path Traversal | 194up
  > > NOTE! Thanks for submitting a report! Please replace *all* the (parenthesized) sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!  ### Summary A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server. The issue...
- [file read on MCS servers via supplying a QCOW2 image with external backing file](https://hackerone.com/reports/1024899) -- Mail.ru | $15,000 | Information Disclosure | 222up
- [Path traversal, to RCE](https://hackerone.com/reports/733072) -- GitLab | $12,000 | Command Injection - Generic | 142up
  > ### Summary This one is similar to #732330 but much simpler. A path traversal issue in GitLab package registry API allow an attacker to write any file at any location writable to user git in a GitLab server.  ### Steps to reproduce  1. Enable package registry in your GitLab instance. 2. Create a project (package registry is enabled by default) 3. Create a private token to call the API 4. Send...
- [Path traversal in Nuget Package Registry](https://hackerone.com/reports/822262) -- GitLab | $12,000 | Path Traversal | 87up
  > ### Summary There's a path traversal issue in Nuget package registry which was released to GitLab-EE recently. The issue allows an attacker to create any file with an extension “.nupkg” in the filesystem. By combining the bug with a race condition in Gitaly which I used several times before (#762421, #732330). It could finally be used to read sensitive files in a GitLab instance.  For some...
- [Arbitrary File Reading on Uber SSL VPN](https://hackerone.com/reports/617543) -- Uber | $6,500 | Plaintext Storage of a Password | 38up
  > The hacker has found a series of 0 day related to Pulse Secure SSL VPN.
- [Mozilla VPN Clients: RCE via file write and path traversal](https://hackerone.com/reports/2995025) -- Mozilla | $6,000 | Path Traversal | 172up
  > The report identifies a path traversal vulnerability in Mozilla VPN's client software that leads to Remote Code Execution (RCE). The vulnerability exists in the "live_reload" command of the client's inspector feature, which can be accessed when the client is in developer mode with "Use Staging Servers" enabled. The vulnerable code in the InspectorHotreloader::fetchAndAnnounce() function fails...
- [LRF on shared.mail.ru due to "markdown" plugin](https://hackerone.com/reports/518641) -- Mail.ru | $6,000 | Path Traversal | 40up
- [Kroki Arbitrary File Read/Write](https://hackerone.com/reports/1098793) -- GitLab | $5,600 | Improper Access Control - Generic | 41up
  > ### Summary  In short, I've found a potentially weird bug in `asciidoctor` that could lead to arbitrary file read/write in `asciidoctor-kroki` even though Gitlab have already made an attempt to disable `kroki-plantuml-include`  **lib/gitlab/asciidoc.rb** ```rb module Gitlab   # Parser/renderer for the AsciiDoc format that uses Asciidoctor and filters   # the resulting HTML through HTML pipeline...
- [Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling](https://hackerone.com/reports/3712279) -- PortSwigger Web Security | $5,000 | Path Traversal | 174up
  > ## Target  Burp Suite Professional 2026.3.3 on Windows.  ## Summary  When Burp Scanner's browser-powered crawler crawls an attacker's website, the website can force Burp to write an attacker-controlled file to an attacker-controlled local path. For example, the PoC writes `calc.exe` into the current user's Startup folder, which triggers command execution when the user next logs in.  The issue...
- [Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49](https://hackerone.com/reports/1394916) -- Internet Bug Bounty | $4,000 | Path Traversal | 96up
  > A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.  If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these...
- [[Android] Directory traversal leading to disclosure of auth tokens](https://hackerone.com/reports/1378889) -- Slack | $3,500 | Path Traversal | 50up
  > Files uploaded to and opened in Slack with specially-crafted names could cause the Android operating system  to overwrite configuration files on customer devices, potentially exposing Slack data to attacker-controlled websites. In order to take advantage of this vulnerability, attackers needed to be in a workspace with the user and  to induce a user to click on a file uploaded to Slack...
- [Path traversal through path stored in Uint8Array in Node.js 20](https://hackerone.com/reports/2256167) -- Internet Bug Bounty | $3,495 | Path Traversal | 44up
  > Path traversal through path stored in Uint8Array (High) - (CVE-2023-39332)  Full Security Advisory: https://nodejs.org/en/blog/vulnerability/october-2023-security-releases
- [User credentials leak and arbitrary local file read/leak due to same-origin-policy violation](https://hackerone.com/reports/136454) -- Internet Bug Bounty | $3,000 | Information Disclosure | 3up
  > Vulnerability details ===================== A vulnerability exists in Flash Player that allows violating the same-origin-policy. An attacker can read sensitive local files and communicate with remote servers. As a result, this allows uploading the content of these local files to an attacker-controlled remote server. In addition, this vulnerability enables an attacker to obtain a user's Windows...

---

- [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) -- TikTok | $2,727 | Server-Side Request Forgery (SSRF) | 162up
- [Path traversal by monkey-patching Buffer internals](https://hackerone.com/reports/2434811) -- Internet Bug Bounty | $2,430 | Path Traversal | 67up
- [CVE-2023-28710 Apache Airflow Spark Provider Arbitrary File Read via JDBC](https://hackerone.com/reports/1966083) -- Internet Bug Bounty | $2,400 | Improper Input Validation | 22up
- [Permission model improperly protects against path traversal in Node.js 20](https://hackerone.com/reports/2225660) -- Internet Bug Bounty | $2,330 | Path Traversal | 42up
- [Worker container escape lead to arbitrary file reading in host machine [again]](https://hackerone.com/reports/697055) -- Semmle | $2,000 | Privilege Escalation | 178up
- [Path traversal, SSTI and RCE on a MailRu acquisition](https://hackerone.com/reports/536130) -- Mail.ru | $2,000 | Code Injection | 152up
- [Arbitrary local system file read on open-xchange server](https://hackerone.com/reports/303744) -- Open-Xchange | $2,000 | Resource Injection | 125up
- [Worker container escape lead to arbitrary file reading in host machine](https://hackerone.com/reports/694181) -- Semmle | $2,000 | Privilege Escalation | 112up
- [GitLab CI runner can read and poison cache of all other projects](https://hackerone.com/reports/301432) -- GitLab | $2,000 | Path Traversal | 43up
- [[JAVA]: Partial Path Traversal](https://hackerone.com/reports/1678405) -- GitHub Security Lab | $1,800 | 3up
- [LFI and SSRF via XXE in emblem editor](https://hackerone.com/reports/347139) -- Rockstar Games | $1,500 | XML External Entities (XXE) | 79up
- [Multiple SQL Injections and constrained LFI in esk-static.3igames.mail.ru](https://hackerone.com/reports/974078) -- Mail.ru | $1,500 | SQL Injection | 41up
- [Path Traversal on Default Installed Rails Application (Asset Pipeline)](https://hackerone.com/reports/307808) -- Ruby on Rails | $1,500 | Path Traversal | 38up
- [Arbitrary file creation with semi-controlled content (leads to DoS, EoP and others) at Steam Windows Client](https://hackerone.com/reports/682774) -- Valve | $1,250 | Path Traversal | 41up
- [Arbitrary read of all SVG files on a Nextcloud server](https://hackerone.com/reports/1302155) -- Nextcloud | $1,250 | Path Traversal | 36up
- [Off-by-slash vulnerability in nodejs.org and iojs.org](https://hackerone.com/reports/1650273) -- Internet Bug Bounty | $1,200 | Path Traversal | 4up
- [Zero day path traversal vulnerability in Grafana 8.x allows unauthenticated arbitrary local file read](https://hackerone.com/reports/1415820) -- Aiven Ltd | $1,000 | Path Traversal | 105up
- [File writing by Directory traversal at actionpack-page_caching and RCE by it](https://hackerone.com/reports/519220) -- Ruby on Rails | $1,000 | Path Traversal | 80up
- [Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49 and 2.4.50 (incomplete fix of CVE-2021-41773) (CVE-2021-42013)](https://hackerone.com/reports/1400238) -- Internet Bug Bounty | $1,000 | Path Traversal | 29up
- [Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.50](https://hackerone.com/reports/1404731) -- Internet Bug Bounty | $1,000 | Path Traversal: '.../...//' | 26up
- [Private file read through file attachment](https://hackerone.com/reports/888929) -- Mail.ru | $1,000 | Insecure Storage of Sensitive Information | 21up
- [Installing a crafted gem package may create or overwrite files](https://hackerone.com/reports/243156) -- RubyGems | $1,000 | Path Traversal | 11up
- [Path Traversal in dict-fs and no-check Escape Character in oauth2-jwt](https://hackerone.com/reports/1132160) -- Open-Xchange | $982 | Path Traversal | 57up
- [Vanilla Forums AddonManager getSingleIndex Directory Traversal File Inclusion Remote Code Execution Vulnerability](https://hackerone.com/reports/411140) -- Vanilla | $900 | Path Traversal | 84up
- [Avatar upload allows arbitrary file overwriting](https://hackerone.com/reports/671605) -- Mail.ru | $750 | Path Traversal | 88up
- [[geekbrains.ru] CVE-2019-5418 Ruby on Rails File Content Disclosure](https://hackerone.com/reports/541858) -- Mail.ru | $750 | Path Traversal | 40up
- [[CS 1.6] Map cycle abuse allows arbitrary file read/write](https://hackerone.com/reports/590279) -- Valve | $750 | Improper Access Control - Generic | 22up
- [Path Traversal в iOS приложении](https://hackerone.com/reports/1050231) -- VK.com | $700 | Path Traversal | 55up
- [PUT Based CSRF via Client Side Path Traversal + Cookie Bomb on Acronis Cloud](https://hackerone.com/reports/1860380) -- Acronis | $600 | Path Traversal | 76up
- [Arbitrary Local-File Read from Admin - Restore From Backup due to Symlinks](https://hackerone.com/reports/213558) -- Discourse | $512 | Information Disclosure | 52up
- [HTML-injection in PDF-export leads to LFI](https://hackerone.com/reports/809819) -- Visma Public | $500 | 330up
- [Delete directory using symlink when decompressing tar](https://hackerone.com/reports/317321) -- RubyGems | $500 | Path Traversal | 35up
- [DNS SRV lookup of file:// sources enables local hijacking of gems](https://hackerone.com/reports/411519) -- RubyGems | $500 | Path Traversal | 22up
- [Local File Read vulnerability on ██████████ [HtUS]](https://hackerone.com/reports/1624670) -- U.S. Dept Of Defense | $500 | PHP Local File Inclusion | 11up
- [[bower] Arbitrary File Write through improper validation of symlinks while package extraction](https://hackerone.com/reports/492512) -- Internet Bug Bounty | $500 | Path Traversal | 7up
- [Phabricator Phame Blog Skins Local File Inclusion](https://hackerone.com/reports/39428) -- Phabricator | $500 | Code Injection | 2up
- [Path traversal in ZIP extract routine on LINE Android](https://hackerone.com/reports/859469) -- LY Corporation | $475 | Path Traversal | 33up
- [Limited LFI](https://hackerone.com/reports/895972) -- GSA Bounty | $300 | Remote File Inclusion | 48up
- [Unsanitized user photo paths allow local file read](https://hackerone.com/reports/484615) -- Vanilla | $300 | Business Logic Errors | 31up
- [[orsotenslimselfie.lady.mail.ru] SQL Injection](https://hackerone.com/reports/115291) -- Mail.ru | $300 | SQL Injection | 2up
- [File Read Vulnerability allows Attackers to Compromise S3 buckets using Prow](https://hackerone.com/reports/1485500) -- Kubernetes | $250 | Improper Access Control - Generic | 26up
- [Linux client is vulnerable to directory traversal when downloading files](https://hackerone.com/reports/590319) -- Nextcloud | $250 | Path Traversal | 14up
- [Access to arbitrary file of the Nextcloud Android app from within the Nextcloud Android app](https://hackerone.com/reports/1408692) -- Nextcloud | $250 | Path Traversal | 12up
- [cgi scripts wordlist entry for windmail.exe has payload that sends arbitrary file read result to third-party](https://hackerone.com/reports/2733994) -- PortSwigger Web Security | $200 | Information Disclosure | 81up
- [Download attachments with traversal path into any sdcard directory (incomplete fix 106097)](https://hackerone.com/reports/284346) -- Mail.ru | $200 | Path Traversal | 7up
- [Fix : (Security) Mitigate Path Traversal Bug](https://hackerone.com/reports/1635321) -- Linux Foundation Decentralized Trust | $200 | Path Traversal | 6up
- [[o2.mail.ru] nginx alias traversal](https://hackerone.com/reports/446330) -- Mail.ru | $150 | Path Traversal | 31up
- [LFI in beta.mail.ru](https://hackerone.com/reports/346825) -- Mail.ru | $150 | 28up
- [Path Traversal When Sharing with Cloud Mail.Ru App via a file with Crated Name](https://hackerone.com/reports/380096) -- Mail.ru | $150 | Path Traversal | 13up
- [Чтение системных данных приложения: данные для авторизации, логи, БД, личная переписка](https://hackerone.com/reports/373909) -- Mail.ru | $150 | Path Traversal | 9up
- [LFI to steal  /etc/passwd - Bypass filter in the <meta property="og:image"> tag via redirect and much more](https://hackerone.com/reports/996899) -- BugPoC | $100 | Path Traversal | 69up
- [jitsi-call-analytics: Unauthenticated arbitrary file write via path traversal in `/api/v1/uploads/analyze`](https://hackerone.com/reports/3485343) -- 8x8 | $100 | Path Traversal | 67up
- [GitHub Security Lab (GHSL) Vulnerability Report: Insufficient path validation in ReceiveExternalFilesActivity.java (GHSL-2022-060)](https://hackerone.com/reports/1650270) -- ownCloud | $50 | Path Traversal | 14up
- [Arbitrary file read via ffmpeg HLS parser at https://www.flickr.com/photos/upload](https://hackerone.com/reports/487008) -- Flickr | Code Injection | 340up
- [SSRF on fleet.city-mobil.ru leads to local file read](https://hackerone.com/reports/748069) -- Mail.ru | Server-Side Request Forgery (SSRF) | 272up
- [Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion](https://hackerone.com/reports/1189367) -- Evernote | Server-Side Request Forgery (SSRF) | 264up
- [Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data](https://hackerone.com/reports/876295) -- Starbucks | Path Traversal | 239up
- [Path traversal in filename in LINE Mac client](https://hackerone.com/reports/727727) -- LY Corporation | Path Traversal | 175up
- [RCE as Admin defeats WordPress hardening and file permissions](https://hackerone.com/reports/436928) -- WordPress | Path Traversal | 164up
- [[portswigger.net] Path Traversal al /cms/audioitems](https://hackerone.com/reports/2424815) -- PortSwigger Web Security | Path Traversal | 145up
- [Directory Traversal in uftpd 2.6-2.10](https://hackerone.com/reports/694141) -- ██████ | 136up
- [Unauthenticated LFI revealing log information](https://hackerone.com/reports/272578) -- Slack | Information Disclosure | 123up
- [Wordpress unzip_file path traversal](https://hackerone.com/reports/205481) -- WordPress | Violation of Secure Design Principles | 119up
- [RCE/LFI on test Jenkins instance due to improper authentication flow](https://hackerone.com/reports/258117) -- Snapchat | Improper Access Control - Generic | 117up
- [Path Traversal Vulnerability in Lila Project](https://hackerone.com/reports/3181066) -- Lichess | Path Traversal: '.../...//' | 116up
- [SSRF and LFI in site-audit tool](https://hackerone.com/reports/794099) -- Semrush | Server-Side Request Forgery (SSRF) | 85up
- [Korea - LFI via path traversal at https://msr.istarbucks.co.kr:6443/appif/](https://hackerone.com/reports/780021) -- Starbucks | Path Traversal | 81up
- [Path traversal lead to LFR via [CVE-2019-3394]](https://hackerone.com/reports/980881) -- Mail.ru | Path Traversal | 74up
- [Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter](https://hackerone.com/reports/3599248) -- Lovable VDP | Open Redirect | 73up
- [Grafana LFI on https://grafana.mariadb.org](https://hackerone.com/reports/1419213) -- MariaDB | Remote File Inclusion | 73up
- [CVE-█████-35813 in █████](https://hackerone.com/reports/2200329) -- Mars | Relative Path Traversal | 71up
- [CVE-2020-3187 - Unauthenticated Arbitrary File Deletion](https://hackerone.com/reports/960330) -- U.S. Dept Of Defense | Path Traversal | 70up
- [Unauthenticated LFI (Local File Inclusion) using the symbol `!` At the target `https://████/`](https://hackerone.com/reports/2778380) -- U.S. Dept Of Defense | Path Traversal | 69up
- [Authenticated path traversal to Stored XSS and Denial-of-Service](https://hackerone.com/reports/2168002) -- phpBB | Cross-site Scripting (XSS) - Stored | 69up
- [Account Takeover / Arbitrary File read and deletion / Partial code execution (intent redirection)](https://hackerone.com/reports/2289836) -- MercadoLibre | Code Injection | 66up
- [Path traversal in deeplink query parameter can expose any user's private info to a public directory (one click)](https://hackerone.com/reports/2553411) -- Basecamp | Path Traversal | 65up
- [Path Traversal Vulnerability in Nextcloud Tables Enables Arbitrary File Exfiltration of Any Files Supported by PhpSpreadsheet Library](https://hackerone.com/reports/3249624) -- Nextcloud | Path Traversal | 63up
- [Path Traversal Vulnerability found on IBM Cloud](https://hackerone.com/reports/3060373) -- IBM | Path Traversal | 63up
- [CVE-2018-0296 Cisco ASA Denial of Service & Path Traversal vulnerable on [mtn.co.ug]](https://hackerone.com/reports/2375666) -- MTN Group | Path Traversal: '.../...//' | 62up
- [Client-Side Path Traversal on LINE Developers Console](https://hackerone.com/reports/2473862) -- LY Corporation | Cross-Site Request Forgery (CSRF) | 61up
- [Unauthenticated Path Traversal and Command Injection in Trellix Enterprise Security Manager 11.6.10](https://hackerone.com/reports/2817658) -- Trellix | OS Command Injection | 60up
- [Path traversal by drive name in Windows environment](https://hackerone.com/reports/2307225) -- Node.js | Path Traversal | 59up
- [LFI with potential to RCE on ██████ using CVE-2019-3396](https://hackerone.com/reports/538771) -- U.S. Dept Of Defense | Remote File Inclusion | 58up
- [ActiveStorage Disk Service Path Traversal via Custom Blob Key Injection](https://hackerone.com/reports/3580511) -- Ruby on Rails | Path Traversal | 57up
- [Arbitrary File Write](https://hackerone.com/reports/3384150) -- arkadiyt-projects | Path Traversal | 56up