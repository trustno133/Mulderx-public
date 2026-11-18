# File Upload -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Arbitrary file read  via the bulk imports UploadsPipeline](https://hackerone.com/reports/1439593) -- GitLab | $29,000 | Path Traversal | 329up
  > ### Summary  The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be read and uploaded when importing a group.  When a group has uploads (such as markdown attachments), an `uploads.tar.gz` file will be downloaded and extracted in the...
- [Arbitrary file read via the UploadsRewriter when moving and issue](https://hackerone.com/reports/827052) -- GitLab | $20,000 | Path Traversal | 1503up
  > ### Summary The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project.  The pattern used to look for references is : ```   MARKDOWN_PATTERN = %r{\!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}.freeze ```  This is used by the `UploadsRewriter` when copying an issue to also copy across...
- [Arbitrary file read during project import](https://hackerone.com/reports/1132378) -- GitLab | $16,000 | Path Traversal | 194up
  > > NOTE! Thanks for submitting a report! Please replace *all* the (parenthesized) sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!  ### Summary A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server. The issue...
- [Arbitrary File Reading on Uber SSL VPN](https://hackerone.com/reports/617543) -- Uber | $6,500 | Plaintext Storage of a Password | 38up
  > The hacker has found a series of 0 day related to Pulse Secure SSL VPN.
- [Kroki Arbitrary File Read/Write](https://hackerone.com/reports/1098793) -- GitLab | $5,600 | Improper Access Control - Generic | 41up
  > ### Summary  In short, I've found a potentially weird bug in `asciidoctor` that could lead to arbitrary file read/write in `asciidoctor-kroki` even though Gitlab have already made an attempt to disable `kroki-plantuml-include`  **lib/gitlab/asciidoc.rb** ```rb module Gitlab   # Parser/renderer for the AsciiDoc format that uses Asciidoctor and filters   # the resulting HTML through HTML pipeline...
- [[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia](https://hackerone.com/reports/1547877) -- Aiven Ltd | $5,000 | Unrestricted Upload of File with Dangerous Type | 56up
  > ## Summary: The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto the server. The HTTP sink connector allows sending HTTP requests to localhost. There is unprotected Jolokia listening on `localhost:6725`.  JMX exports the `com.sun.management:type=DiagnosticCommand` MBean, which contains the `jvmtiAgentLoad` operation. This...
- [Unrestricted file upload on [ambassador.mail.ru]](https://hackerone.com/reports/854032) -- Mail.ru | $3,000 | Code Injection | 404up
- [CVE-2023-28710 Apache Airflow Spark Provider Arbitrary File Read via JDBC](https://hackerone.com/reports/1966083) -- Internet Bug Bounty | $2,400 | Improper Input Validation | 22up
  > CVE-2023-28710: Apache Airflow Spark Provider Arbitrary File Read via JDBC  Severity: low  Description: Improper Input Validation vulnerability in Apache Software Foundation Apache Airflow Spark Provider.This issue affects Apache Airflow Spark Provider: before 4.0.1.  Credit: Xie Jianming of Nsfocus (finder)  Full Security Advisory: https://lists.apache.org/thread/lb9w9114ow00h2nkn8bjm106v5x1p1d2
- [Worker container escape lead to arbitrary file reading in host machine [again]](https://hackerone.com/reports/697055) -- Semmle | $2,000 | Privilege Escalation | 178up
  > ## Summary: After a successful build, LGTM allow user to view the file list. By default, only source code files and build config files are reserved (``lgtm.yml`` and ``.lgtm.yml``). If there are both files in folder, LGTM will process ``lgtm.yml`` file and skip ``.lgtm.yml``, but it still keeps both of files in directory. By making symlink to ``.lgtm.yml`` file, after successful build, it will...
- [Worker container escape lead to arbitrary file reading in host machine](https://hackerone.com/reports/694181) -- Semmle | $2,000 | Privilege Escalation | 112up
  > ## Summary: Because lack of security, attacker will be able to remove original log file and replace it will a symlink to other file,  After finishing job, host machine copy file from docker container. Because the original log file has been removed, the host machine will copy the symlink file. But the problem is it doesn't copy the linked file in container, it copys the linked file in the HOST...
- [Tricking the "Create snippet" feature into displaying the wrong filetype can lead to RCE on Slack users](https://hackerone.com/reports/833080) -- Slack | $1,500 | Unrestricted Upload of File with Dangerous Type | 101up
  > An issue in Slack's Create snippet feature results in filetypes being displayed incorrectly. This can lead to RCE if a Slack user downloads an executable file thinking that it is a CSV or other benign file type.
- [Arbitrary File Write as SYSTEM from unprivileged user](https://hackerone.com/reports/583184) -- Valve | $1,250 | Privilege Escalation | 71up
  > ### Note: This report was reviewed and updated after a correction to program scope.       Vulnerability ========  The Steam Client installs a "Steam Client Service" that runs as SYSTEM to update the steam application. This service executes from C:\Program Files (x86)\Common\Steam where permissions are properly set to only allow modification from SYSTEM or the Administrators group.  If the...
- [Arbitrary file creation with semi-controlled content (leads to DoS, EoP and others) at Steam Windows Client](https://hackerone.com/reports/682774) -- Valve | $1,250 | Path Traversal | 41up
  > The vulnerability allows to create arbitrary file with some crafted text (or append to existing file). Tested on actual version 5.31.28.21 (SteamService.exe filevesion info). At start of the report I describe how to trigger vulnerability, than describe how to cause any consequences.  How to trigger - 1. Environment Close Steam application and stop "Steam Client Service", if it is...
- [e.mail.ru: File upload "Chapito" circus](https://hackerone.com/reports/20616) -- Mail.ru | $1,000 | Memory Corruption - Generic | 2up
- [Avatar upload allows arbitrary file overwriting](https://hackerone.com/reports/671605) -- Mail.ru | $750 | Path Traversal | 88up

---

- [Drive-by arbitrary file deletion in the GDK via letter_opener_web gem](https://hackerone.com/reports/1353103) -- GitLab | $750 | Cross-Site Request Forgery (CSRF) | 27up
- [[CS 1.6] Map cycle abuse allows arbitrary file read/write](https://hackerone.com/reports/590279) -- Valve | $750 | Improper Access Control - Generic | 22up
- [Cross site scripting via file upload in subdomain ads.tiktok.com](https://hackerone.com/reports/1433125) -- TikTok | $500 | Cross-site Scripting (XSS) - Stored | 65up
- [Private application files can be uploaded to Slack via malicious uploader](https://hackerone.com/reports/375083) -- Slack | $500 | Information Disclosure | 38up
- [[bower] Arbitrary File Write through improper validation of symlinks while package extraction](https://hackerone.com/reports/492512) -- Internet Bug Bounty | $500 | Path Traversal | 7up
- [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/808862) -- Visma Public | $250 | Unrestricted Upload of File with Dangerous Type | 268up
- [Arbitrary File Upload to Stored XSS](https://hackerone.com/reports/808821) -- Visma Public | $250 | Cross-site Scripting (XSS) - Stored | 245up
- [Unrestricted file upload when creating quotes allows for Stored XSS](https://hackerone.com/reports/788397) -- Visma Public | $250 | Unrestricted Upload of File with Dangerous Type | 57up
- [Unrestricted File Upload Blind Stored Xss  in subdomain ads.tiktok.com](https://hackerone.com/reports/1577370) -- TikTok | $250 | Cross-site Scripting (XSS) - Stored | 38up
- [Access to arbitrary file of the Nextcloud Android app from within the Nextcloud Android app](https://hackerone.com/reports/1408692) -- Nextcloud | $250 | Path Traversal | 12up
- [cgi scripts wordlist entry for windmail.exe has payload that sends arbitrary file read result to third-party](https://hackerone.com/reports/2733994) -- PortSwigger Web Security | $200 | Information Disclosure | 81up
- [reports.breadcrumb.com is vulnerable for Arbitrary file existence disclosur CVE-2014-7829](https://hackerone.com/reports/329218) -- Upserve | $200 | Information Disclosure | 14up
- [File upload XSS (Java applet) on http://slackatwork.com/](https://hackerone.com/reports/97657) -- Slack | $200 | Command Injection - Generic | 1up
- [cloud.mail.ru: File upload XSS using Content-Type header](https://hackerone.com/reports/20720) -- Mail.ru | $150 | Cross-site Scripting (XSS) - Generic | 1up
- [jitsi-call-analytics: Unauthenticated arbitrary file write via path traversal in `/api/v1/uploads/analyze`](https://hackerone.com/reports/3485343) -- 8x8 | $100 | Path Traversal | 67up
- [Unrestricted File Upload on reddit.secure.force.com](https://hackerone.com/reports/1606957) -- Reddit | $100 | 34up
- [Unrestricted file upload on the image of contacts](https://hackerone.com/reports/808287) -- Nextcloud | $100 | Business Logic Errors | 24up
- [Webshell via File Upload on ecjobs.starbucks.com.cn](https://hackerone.com/reports/506646) -- Starbucks | OS Command Injection | 688up
- [Arbitrary file read via ffmpeg HLS parser at https://www.flickr.com/photos/upload](https://hackerone.com/reports/487008) -- Flickr | Code Injection | 340up
- [Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg](https://hackerone.com/reports/1027822) -- Starbucks | Improper Access Control - Generic | 247up
- [Unrestricted file upload in www.semrush.com > /my_reports/api/v1/upload/image](https://hackerone.com/reports/748903) -- Semrush | Violation of Secure Design Principles | 133up
- [Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover](https://hackerone.com/reports/3115705) -- Dust | Cross-site Scripting (XSS) - Stored | 118up
- [Unrestricted File Upload on https://partner.tiktokshop.com/wsos_v2/oec_partner/upload](https://hackerone.com/reports/1890284) -- TikTok | Unrestricted Upload of File with Dangerous Type | 118up
- [Insecure file upload in xiaoai.mi.com Lead to Stored  XSS](https://hackerone.com/reports/882733) -- Xiaomi | Cross-site Scripting (XSS) - Stored | 117up
- [[insideok.ru] Remote Command Execution via file upload.](https://hackerone.com/reports/666716) -- ok.ru | Command Injection - Generic | 98up
- [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/880099) -- GitLab | Cross-site Scripting (XSS) - Stored | 89up
- [Unrestricted File Upload at ██████████](https://hackerone.com/reports/2357778) -- Mars | Unrestricted Upload of File with Dangerous Type | 78up
- [CVE-2020-3187 - Unauthenticated Arbitrary File Deletion](https://hackerone.com/reports/960330) -- U.S. Dept Of Defense | Path Traversal | 70up
- [Account Takeover / Arbitrary File read and deletion / Partial code execution (intent redirection)](https://hackerone.com/reports/2289836) -- MercadoLibre | Code Injection | 66up
- [Path Traversal Vulnerability in Nextcloud Tables Enables Arbitrary File Exfiltration of Any Files Supported by PhpSpreadsheet Library](https://hackerone.com/reports/3249624) -- Nextcloud | Path Traversal | 63up
- [Singapore - Unrestricted File Upload Leads to XSS on campaign.starbucks.com.sg/api/upload](https://hackerone.com/reports/883151) -- Starbucks | Cross-site Scripting (XSS) - Stored | 61up
- [Unrestricted File Upload Results in Cross-Site Scripting Attacks](https://hackerone.com/reports/1005355) -- Uber | Cross-site Scripting (XSS) - Stored | 58up
- [Unauthenticated File Upload to CDN](https://hackerone.com/reports/3589247) -- Enjin | Improper Access Control - Generic | 56up
- [Arbitrary File Write](https://hackerone.com/reports/3384150) -- arkadiyt-projects | Path Traversal | 56up
- [insecure storage of information, you can view any file uploaded to the server without authentication and only with a single link](https://hackerone.com/reports/2007235) -- Radancy | Insecure Storage of Sensitive Information | 55up
- [Git flag injection leads to arbitrary file write](https://hackerone.com/reports/1070247) -- Phabricator | Path Traversal | 54up
- [SELECT ... INTO OUTFILE does not enforce the FILE WRITE privilege  unprivileged arbitrary file write on the   server](https://hackerone.com/reports/3780695) -- SingleStore | Missing Authorization | 50up
- [Author → arbitrary file deletion anywhere on disk (site takeover) via `POST /wp/v2/media/<id>/finalize` poisoning `_wp_attachment_metadata`](https://hackerone.com/reports/3931777) -- WordPress | Path Traversal | 47up
- [China - ecjobsdc.starbucks.com.cn html/shtml file upload vulnerability](https://hackerone.com/reports/412481) -- Starbucks | Privilege Escalation | 46up
- [Arbitrary file read from Cloudflare Pages build environment](https://hackerone.com/reports/1570874) -- Cloudflare Public Bug Bounty | 40up
- [Arbitrary file write triggered by deeplink abuse - MetaMask Android](https://hackerone.com/reports/1768166) -- MetaMask | Business Logic Errors | 40up
- [Arbitrary File Reading leads to RCE in the Pulse Secure SSL VPN on the https://████](https://hackerone.com/reports/695005) -- U.S. Dept Of Defense | File and Directory Information Exposure | 39up
- [Arbitrary file creation via symlink attack on syncagentsrv (Acronis Sync Agent Service)](https://hackerone.com/reports/945122) -- Acronis | Privilege Escalation | 38up
- [Non-authenticated path traversal leading to arbitrary file read](https://hackerone.com/reports/1096043) -- ExpressionEngine | Path Traversal | 34up
- [RCE via File Upload  with a Null Byte Truncated File Extension at https://██████/](https://hackerone.com/reports/2054184) -- U.S. Dept Of Defense | Command Injection - Generic | 33up
- [No validation to Image upload user can upload ( php APK zip files and can be used as storage purpose)](https://hackerone.com/reports/1644062) -- Linktree | Unrestricted Upload of File with Dangerous Type | 32up
- [Arbitrary File Read via file:// Protocol in cURL](https://hackerone.com/reports/3242087) -- curl | Path Traversal | 31up
- [Arbitrary File Reading leads to RCE in the Pulse Secure SSL VPN on the https://██████ (███)](https://hackerone.com/reports/696276) -- U.S. Dept Of Defense | Path Traversal | 31up
- [Windows only: arbitrary file read vulnerability in openssl s_server](https://hackerone.com/reports/850775) -- Internet Bug Bounty | Path Traversal | 31up
- [[IRCCloud Android] Theft of arbitrary files leading to token leakage](https://hackerone.com/reports/288955) -- IRCCloud | Privacy Violation | 31up
- [Unrestricted File Upload](https://hackerone.com/reports/184596) -- U.S. Dept Of Defense | Command Injection - Generic | 31up
- [Arbitrary File delete via PHAR deserialization](https://hackerone.com/reports/921288) -- Concrete CMS | Deserialization of Untrusted Data | 28up
- [CVE-2020-3187 - unauthenticated arbitrary file deletion in Cisco](https://hackerone.com/reports/944665) -- QIWI | Path Traversal | 26up
- [Leak arbitrary file under nextcloud android client privacy directory](https://hackerone.com/reports/1142918) -- Nextcloud | 25up
- [Unrestricted File Upload on https://app.lemlist.com](https://hackerone.com/reports/722919) -- lemlist | Unrestricted Upload of File with Dangerous Type | 24up
- [SSRF & unrestricted file upload on https://my.stripo.email/](https://hackerone.com/reports/771382) -- Stripo Inc | Server-Side Request Forgery (SSRF) | 24up
- [File Upload XSS in image uploading of App in mopub](https://hackerone.com/reports/97672) -- X / xAI | Cross-site Scripting (XSS) - Generic | 24up
- [[SFTP] TOCTOU Race Condition in Upload Resume Logic Leads to Arbitrary File Append](https://hackerone.com/reports/3432833) -- curl | Time-of-check Time-of-use (TOCTOU) Race Condition | 23up
- [Unrestricted File Upload on https://auth.ratelimited.me](https://hackerone.com/reports/463604) -- RATELIMITED | 23up
- [[Quora Android] Possible to steal arbitrary files from mobile device](https://hackerone.com/reports/258460) -- Quora | Information Disclosure | 23up
- [Low privileges (auth) Remote Command Execution - PHP file upload bypass.](https://hackerone.com/reports/841397) -- ExpressionEngine | Code Injection | 22up
- [Malicious file upload (secure.lahitapiola.fi)](https://hackerone.com/reports/305237) -- LocalTapiola | Violation of Secure Design Principles | 22up
- [Arbitrary File Reading leads to RCE in the Pulse Secure SSL VPN on the https://███](https://hackerone.com/reports/678496) -- U.S. Dept Of Defense | OS Command Injection | 21up
- [Arbritrary file Upload on AirMax](https://hackerone.com/reports/73480) -- Ubiquiti Inc. | Path Traversal | 21up
- [Uncontrolled File Write/Arbitrary File Creation](https://hackerone.com/reports/3250117) -- curl | Code Injection | 20up
- [[doc.rt.informaticacloud.com] Arbitrary File Reading via Double URL Encode](https://hackerone.com/reports/232371) -- Informatica | Path Traversal | 20up
- [Unrestricted Upload of File with Dangerous Type](https://hackerone.com/reports/1081766) -- Enjin | Business Logic Errors | 20up
- [Path traversal on https://███ allows arbitrary file read (CVE-2020-3452)](https://hackerone.com/reports/936399) -- U.S. Dept Of Defense | Path Traversal | 20up
- [Unauthenticated arbitrary file upload on the https://█████/ (█████████)](https://hackerone.com/reports/698789) -- U.S. Dept Of Defense | Violation of Secure Design Principles | 19up
- [https://██████ vulnerable to CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD](https://hackerone.com/reports/1031437) -- U.S. Dept Of Defense | Improper Authentication - Generic | 19up
- [Unrestricted File Upload in Chat Window](https://hackerone.com/reports/826288) -- Qulture.Rocks | Deserialization of Untrusted Data | 19up
- [Arbitrary file deletion in wp-core - guides towards RCE and information disclosure](https://hackerone.com/reports/291878) -- WordPress | Path Traversal | 17up
- [[█████] Bug Reports allow for Unrestricted File Upload](https://hackerone.com/reports/1850065) -- U.S. Dept Of Defense | Violation of Secure Design Principles | 16up
- [Arbitrary File Read at ███ via filename parameter](https://hackerone.com/reports/1436223) -- U.S. Dept Of Defense | Path Traversal | 16up
- [Path Traversal in file:// protocol allows Arbitrary File Read](https://hackerone.com/reports/3445174) -- curl | Path Traversal | 15up
- [Arbitrary Files and Folders Deletion vulnerability with Acronis Managed Machine Service](https://hackerone.com/reports/959815) -- Acronis | Privilege Escalation | 15up
- [Arbitrary file download due to bad handling of Redirects in WebTorrent](https://hackerone.com/reports/975514) -- Brave Software | Code Injection | 15up
- [Unrestricted File Upload Leads to XSS & Potential RCE](https://hackerone.com/reports/900179) -- U.S. Dept Of Defense | Unrestricted Upload of File with Dangerous Type | 15up
- [Arbitrary File Download as Shopmanager](https://hackerone.com/reports/402473) -- Automattic | Path Traversal | 15up
- [[bower] Arbitrary File Write through improper validation of symlinks while package extraction](https://hackerone.com/reports/473811) -- Node.js third-party modules | Path Traversal | 15up
- [Content-Security Policy bypass with File Uploads](https://hackerone.com/reports/1380157) -- Rocket.Chat | 14up
- [Arbitrary file read in Rocket.Chat-Desktop](https://hackerone.com/reports/943737) -- Rocket.Chat | 14up
- [SVG file upload leads to XML injection](https://hackerone.com/reports/845832) -- Lab45 | XML Injection | 14up
- [Unrestricted file upload (RCE)](https://hackerone.com/reports/343726) -- Node.js third-party modules | Path Traversal | 14up
- [curl External-Controlled Filename in `--url @file` Leads to Arbitrary File Overwrite](https://hackerone.com/reports/3766392) -- curl | External Control of File Name or Path | 13up