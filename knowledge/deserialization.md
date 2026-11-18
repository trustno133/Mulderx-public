# Deserialization -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Deserialization of untrusted data at https://www.redtube.com/media/hls?s=data](https://hackerone.com/reports/1312641) -- Pornhub | $10,000 | Deserialization of Untrusted Data | 271up
- [Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration](https://hackerone.com/reports/1529790) -- Aiven Ltd | $5,000 | Deserialization of Untrusted Data | 45up
  > ## Summary: When configuring the connector via the Aiven API or the Kafka Connect REST API, the attacker can set the `database.history.producer.sasl.jaas.config` connector property for the `io.debezium.connector.mysql.MySqlConnector` connector. This is likely true for other debezium connectors too.  By setting the connector value to `"com.sun.security.auth.module.JndiLoginModule required...
- [Java: Unsafe deserialization with Jackson](https://hackerone.com/reports/1287573) -- GitHub Security Lab | $4,500 | 26up
- [Java: Query for detecting unsafe deserialization with Spring exporters](https://hackerone.com/reports/1135877) -- GitHub Security Lab | $4,500 | 15up
- [[C#]: Deserialization sinks](https://hackerone.com/reports/1319270) -- GitHub Security Lab | $4,500 | 1up
- [CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet](https://hackerone.com/reports/3031518) -- Internet Bug Bounty | $4,323 | Deserialization of Untrusted Data | 56up
  > The original implementation of partial PUT used a temporary file based on the user provided file name and path with the path separator replaced by ".".  If all of the following were true, a malicious user was able to view security sensitive files and/or inject content into those files: - writes enabled for the default servlet (disabled by default) - support for partial PUT (enabled by...
- [connect.8x8.com: Deserialization Vulnerability  in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)](https://hackerone.com/reports/3861550) -- 8x8 | $3,000 | Deserialization of Untrusted Data | 48up
  > @kyotozzx reported a deserialization vulnerability in the 8x8 Connect Automation Builder's HTTP request step. The vulnerability occurred when server-side template evaluation exposed Newtonsoft JSON objects directly to the Jint JavaScript engine. By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with...
- [[Java] CWE-502: Unsafe deserialization with three JSON frameworks](https://hackerone.com/reports/1368720) -- GitHub Security Lab | $1,800 | 7up
- [Java: CodeQL query for unsafe RMI deserialization](https://hackerone.com/reports/1241579) -- GitHub Security Lab | $1,800 | 4up
- [Remote code execution on rubygems.org](https://hackerone.com/reports/274990) -- RubyGems | $1,500 | Deserialization of Untrusted Data | 50up
  > An unsafe object deserialization vulnerability was found in RubyGems. Unfortunately this vulnerability can be used as a way to escalate to a remote code execution exploit.
- [[CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day](https://hackerone.com/reports/1425474) -- Acronis | $1,000 | Deserialization of Untrusted Data | 75up
  > ## Summary The website at nps.acronis.com is vulnerable to CVE-2021-44228  ## Steps To Reproduce I used this [script](https://github.com/fullhunt/log4j-scan) to find this. It spins up an interact-sh server to receive the callback and send the payload in the query string and about 30 diffent headers. You can reproduce manually with curl and interact-sh/burp collaborator/a server you control....
- [Loading YAML in Java client can lead to command execution](https://hackerone.com/reports/1167773) -- Kubernetes | $1,000 | Deserialization of Untrusted Data | 45up
  > The io.kubernetes.client.util.Yaml file in the Kubernetes client library for Java uses a popular library SnakeYAML to serialize and deserialize YAML. The library has a feature which makes it possible to initiate instances of Java classes by using a YAML tag like !!some.Class [ "argument1" ]. More info about this feature can be found in the docs. This can be used to execute arbitrary code during...
- [Use-after-free vulnerability in SPL(ArrayObject, unserialize)](https://hackerone.com/reports/114078) -- Internet Bug Bounty | $1,000 | Code Injection | 1up
  > https://bugs.php.net/bug.php?id=71311
- [Use-after-free vulnerability in SPL(SplObjectStorage, unserialize)](https://hackerone.com/reports/114079) -- Internet Bug Bounty | $1,000 | Code Injection | 1up
  > https://bugs.php.net/bug.php?id=71313
- [Buffer Over-read in unserialize when parsing Phar](https://hackerone.com/reports/73238) -- Internet Bug Bounty | $1,000 | 1up
  > https://bugs.php.net/bug.php?id=69324  ext/phar/phar.c in PHP before 5.4.40, 5.5.x before 5.5.24, and 5.6.x before 5.6.8 allows remote attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read and application crash) via a crafted length value in conjunction with crafted serialized data in a phar archive, related to the phar_parse_metadata and...

---

- [Untrusted deserialization issue when loading newrelic.yml file in Java agent leads to code execution on host](https://hackerone.com/reports/1109620) -- New Relic | $768 | Deserialization of Untrusted Data | 39up
- [Vanilla Forums ImportController index file_exists Unserialize Remote Code Execution Vulnerability](https://hackerone.com/reports/410237) -- Vanilla | $600 | Deserialization of Untrusted Data | 39up
- [Vanilla Forums domGetImages getimagesize Unserialize Remote Code Execution Vulnerability (critical)](https://hackerone.com/reports/410882) -- Vanilla | $600 | Deserialization of Untrusted Data | 32up
- [Vanilla Forums Gdn_Format unserialize() Remote Code Execution Vulnerability](https://hackerone.com/reports/407552) -- Vanilla | $600 | Deserialization of Untrusted Data | 25up
- [Out of bounds memory read in unserialize()](https://hackerone.com/reports/200909) -- Internet Bug Bounty | $500 | Out-of-bounds Read | 6up
- [PHP WDDX Deserialization Heap OOB Read in timelib_meridian()](https://hackerone.com/reports/248659) -- Internet Bug Bounty | $500 | Buffer Over-read | 2up
- [Integer overflow in _pickle.c](https://hackerone.com/reports/73259) -- Internet Bug Bounty | $500 | 1up
- [PHP yaml_parse/yaml_parse_file/yaml_parse_url Unsafe Deserialization](https://hackerone.com/reports/73257) -- Internet Bug Bounty | $500 | 1up
- [Integer overflow in unserialize() (32-bits only)](https://hackerone.com/reports/104012) -- Internet Bug Bounty | $500
- [Vanilla Forums Xenforo password splitHash Unserialize Remote Code Execution Vulnerability](https://hackerone.com/reports/410212) -- Vanilla | $300 | Deserialization of Untrusted Data | 24up
- [Code Injection via Insecure Yaml.load](https://hackerone.com/reports/1051192) -- Kubernetes | $250 | Code Injection | 17up
- [RCE vulnerability in Hyperledger Fabric SDK for Java](https://hackerone.com/reports/801370) -- Linux Foundation Decentralized Trust | $200 | Deserialization of Untrusted Data | 12up
- [RCE via exposed JMX server on jabber.37signals.com/jabber.basecamp.com](https://hackerone.com/reports/1456063) -- Basecamp | $100 | Deserialization of Untrusted Data | 30up
- [unchecked unserialize usages in audit-trail-extension/audit-trail-extension.php](https://hackerone.com/reports/185909) -- Ian Dunn | $50 | 9up
- [unchecked unserialize usage in WordPress-Functionality-Plugin-Skeleton/functionality-plugin-skeleton.php](https://hackerone.com/reports/185907) -- Ian Dunn | $25 | 7up
- [Attacker can add arbitrary data to the blockchain without paying gas](https://hackerone.com/reports/396954) -- Rootstock Labs | Deserialization of Untrusted Data | 258up
- [MobileIron Unauthenticated RCE on mdm.qiwi.com with WAF bypass](https://hackerone.com/reports/983548) -- QIWI | Deserialization of Untrusted Data | 148up
- [Account takeover via insecure intent handling](https://hackerone.com/reports/2516732) -- Basecamp | Deserialization of Untrusted Data | 136up
- [SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai](https://hackerone.com/reports/1842674) -- Krisp | Deserialization of Untrusted Data | 119up
- [Unserialize leading to arbitrary PHP function invoke](https://hackerone.com/reports/210741) -- Rockstar Games | Code Injection | 119up
- [Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]](https://hackerone.com/reports/453791) -- PayPal | Deserialization of Untrusted Data | 93up
- [[RCE] Unserialize to XXE - file disclosure on ams.upload.pornhub.com](https://hackerone.com/reports/142562) -- Pornhub | Information Disclosure | 90up
- [Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce](https://hackerone.com/reports/403083) -- Automattic | Deserialization of Untrusted Data | 84up
- [RCE on Wordpress website](https://hackerone.com/reports/2248328) -- Nextcloud | Deserialization of Untrusted Data | 83up
- [Two click Account Takeover](https://hackerone.com/reports/3079738) -- Basecamp | Deserialization of Untrusted Data | 77up
- [GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]](https://hackerone.com/reports/198734) -- Internet Bug Bounty | Code Injection | 68up
- [insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)](https://hackerone.com/reports/3090123) -- Mars | Deserialization of Untrusted Data | 59up
- [Remote Code Execution through DNN Cookie Deserialization](https://hackerone.com/reports/876708) -- U.S. Dept Of Defense | OS Command Injection | 56up
- [Unsafe yaml load can lead to remote code execution](https://hackerone.com/reports/2467232) -- Liberapay | Deserialization of Untrusted Data | 55up
- [Java Deserialization RCE via JBoss on card.starbucks.in](https://hackerone.com/reports/221294) -- Starbucks | Code Injection | 48up
- [CVE-2017-9822 DotNetNuke Cookie Deserialization Remote Code Execution (RCE) on lonidoor.mtn.ci](https://hackerone.com/reports/2762119) -- MTN Group | Code Injection | 46up
- [Remote Code Execution via Insecure Deserialization in Telerik UI](https://hackerone.com/reports/838196) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 45up
- [Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in](https://hackerone.com/reports/153026) -- Starbucks | Code Injection | 42up
- [Remote Code Execution (RCE) in a Sony WebSystem](https://hackerone.com/reports/329572) -- Sony | Deserialization of Untrusted Data | 40up
- [Type Juggling -> PHP Object Injection -> SQL Injection Chain](https://hackerone.com/reports/202774) -- ExpressionEngine | Cryptographic Issues - Generic | 40up
- [[Switch, PIA/MK8DX] Stack buffer overflow and potential RCE in PIA (LAN/LDN, possibly NEX) room info deserialization](https://hackerone.com/reports/2611669) -- Nintendo | Stack Overflow | 36up
- [Remote Code Execution on ██.8x8.com via .NET VSTATE Deserialization](https://hackerone.com/reports/1391576) -- 8x8 | Code Injection | 36up
- [CVE-2023-46132](https://hackerone.com/reports/2255968) -- Linux Foundation Decentralized Trust | Deserialization of Untrusted Data | 34up
- [Navgraph confusion allows any 3p app to send and read requests from the server at app.hey.com](https://hackerone.com/reports/2552879) -- Basecamp | Deserialization of Untrusted Data | 31up
- [[HTAF4-213] [Pre-submission] Unsafe AMF deserialization (CVE-2017-5641) in Apache Flex BlazeDS at the https://www.███████/daip/messagebroker/amf](https://hackerone.com/reports/728614) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 28up
- [Bundler's RCE with response using Marshal](https://hackerone.com/reports/1119120) -- RubyGems | Deserialization of Untrusted Data | 28up
- [Arbitrary File delete via PHAR deserialization](https://hackerone.com/reports/921288) -- Concrete CMS | Deserialization of Untrusted Data | 28up
- [Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935)](https://hackerone.com/reports/1174185) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 27up
- [Remote Code Execution (RCE) in a Sony Pictures WebSystem](https://hackerone.com/reports/330028) -- Sony | Deserialization of Untrusted Data | 22up
- [CTF Writeup flag{cha1n1ng_bugs_f0r_fun_4nd_pr0f1t?_or_rep0rt_an_LF1}](https://hackerone.com/reports/415275) -- h1-5411-CTF | Deserialization of Untrusted Data | 21up
- [Unrestricted File Upload in Chat Window](https://hackerone.com/reports/826288) -- Qulture.Rocks | Deserialization of Untrusted Data | 19up
- [Unsafe deserialization in Libera Pay allows to escalate a SQL injection to Remote Command Execution](https://hackerone.com/reports/361341) -- Liberapay | Deserialization of Untrusted Data | 18up
- [Object injection in `stripe-billing-typographic` GitHub project via /auth/login](https://hackerone.com/reports/1183335) -- Stripe | Resource Injection | 17up
- [Remote Code Execution via CVE-2019-18935](https://hackerone.com/reports/913695) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 17up
- [Pickle deserialization vulnerability in XComs](https://hackerone.com/reports/2334460) -- Internet Bug Bounty | Deserialization of Untrusted Data | 16up
- [Remote Code Execution through Deserialization Attack in OwnBackup app.](https://hackerone.com/reports/562335) -- ownCloud | Deserialization of Untrusted Data | 16up
- [[Git Gud] GitHub.com Svnbridge memcached deserialization vulnerability chain leading to Remote Code Execution](https://hackerone.com/reports/1593913) -- GitHub | Deserialization of Untrusted Data | 14up
- [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329397) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 13up
- [Remote attacker can impersonate Social users via ActivityPub API](https://hackerone.com/reports/461308) -- Nextcloud | Deserialization of Untrusted Data | 12up
- [PHP Object injection -> Building Custom Gadget chain -> RCE](https://hackerone.com/reports/1820492) -- ExpressionEngine | Command Injection - Generic | 11up
- [Deserialization of Untrusted Data in www/delivery/dxmlrpc.php](https://hackerone.com/reports/542670) -- Revive Adserver | Deserialization of Untrusted Data | 11up
- [Heap Use After Free Read in unserialize()](https://hackerone.com/reports/261335) -- Internet Bug Bounty | Use After Free | 11up
- [wpjobmanager - unserialize of user input](https://hackerone.com/reports/308489) -- Automattic | 11up
- [ZipArchive class Use After Free Vulnerability in PHP's GC algorithm and unserialize](https://hackerone.com/reports/146235) -- Internet Bug Bounty | Code Injection | 11up
- [Use After Free Vulnerability in PHP's GC algorithm and unserialize](https://hackerone.com/reports/146233) -- Internet Bug Bounty | Code Injection | 11up
- [Password reset Token not expiring](https://hackerone.com/reports/220185) -- Skyliner | Deserialization of Untrusted Data | 10up
- [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329376) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 9up
- [Deserialization of potentially malicious data to RCE](https://hackerone.com/reports/1415436) -- Django | Deserialization of Untrusted Data | 8up
- [Use After Free Vulnerability in SNMP with GC and unserialize()](https://hackerone.com/reports/152266) -- Internet Bug Bounty | Memory Corruption - Generic | 8up
- [h1-5411-CTF report: LFI / Deserialization / XXE vulnerability,](https://hackerone.com/reports/415233) -- h1-5411-CTF | Command Injection - Generic | 8up
- [Insecure implementation of deserialization in cryo](https://hackerone.com/reports/350418) -- Node.js third-party modules | Code Injection | 8up
- [Out of Bounds Memory Read in unserialize()](https://hackerone.com/reports/261336) -- Internet Bug Bounty | Buffer Over-read | 7up
- [Heap Use After Free in unserialize()](https://hackerone.com/reports/261338) -- Internet Bug Bounty | Use After Free | 7up
- [Insecure implementation of deserialization in funcster](https://hackerone.com/reports/350401) -- Node.js third-party modules | Code Injection | 7up
- [Object Injection in Woocommerce / Handle PDT Responses from PayPal](https://hackerone.com/reports/245228) -- Automattic | 7up
- [Use-after-free in PHP7's unserialize()](https://hackerone.com/reports/245956) -- Internet Bug Bounty | Use After Free | 6up
- [Type Confusion in WDDX Packet Deserialization](https://hackerone.com/reports/114339) -- Internet Bug Bounty | 6up
- [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329399) -- U.S. Dept Of Defense | Deserialization of Untrusted Data | 6up
- [CVE-2017-5929: Hyperledger - Arbitrary Deserialization of Untrusted Data](https://hackerone.com/reports/1739099) -- Linux Foundation Decentralized Trust | 5up
- [Phar Deserialization Vulnerability via Logging Settings](https://hackerone.com/reports/1063039) -- Concrete CMS | Deserialization of Untrusted Data | 5up
- [Unsafe deserialization in Nexus Repository helm plugin](https://hackerone.com/reports/917843) -- Central Security Project | Deserialization of Untrusted Data | 5up
- [Use-after-free in unserialize()](https://hackerone.com/reports/175982) -- Internet Bug Bounty | Memory Corruption - Generic | 5up
- [Use After Free in PHP7 unserialize()](https://hackerone.com/reports/182474) -- Internet Bug Bounty | Memory Corruption - Generic | 5up
- [[Java]: CWE-502 Add UnsafeDeserialization sinks](https://hackerone.com/reports/1241575) -- GitHub Security Lab | 4up
- [Create an Unexpected Object and Don't Invoke __wakeup() in Deserialization](https://hackerone.com/reports/198723) -- Internet Bug Bounty | 4up
- [Use After Free in unserialize()](https://hackerone.com/reports/198732) -- Internet Bug Bounty | Use After Free | 4up
- [Use-after-free in ArrayObject Deserialization](https://hackerone.com/reports/180909) -- Internet Bug Bounty | Use After Free | 4up
- [NULL Pointer Dereference in WDDX Packet Deserialization with PDORow](https://hackerone.com/reports/180908) -- Internet Bug Bounty | Memory Corruption - Generic | 4up
- [Create an Unexpected Object and Don't Invoke __wakeup() in During Deserialization](https://hackerone.com/reports/159943) -- Internet Bug Bounty | 4up
- [Use After Free Vulnerability in unserialize()](https://hackerone.com/reports/159948) -- Internet Bug Bounty | Memory Corruption - Generic | 4up