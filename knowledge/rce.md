# RCE / Command Injection -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Remote Command Execution via Github import](https://hackerone.com/reports/1679624) -- GitLab | $33,510 | Command Injection - Generic | 391up
  > ### Summary  This is very similar to https://about.gitlab.com/releases/2022/08/22/critical-security-release-gitlab-15-3-1-released/#Remote%20Command%20Execution%20via%20Github%20import and allows arbitrary redis commands to be injected when imported a GitHub repository.  When importing a GitHub repo the api client uses `Sawyer` for handling the responses. This takes a json hash and converts it...
- [RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)](https://hackerone.com/reports/1609965) -- GitLab | $33,510 | Command Injection - Generic | 386up
  > ### Summary  The `DecompressedArchiveSizeValidator` is used to check the size of a archive before extracting it:  https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/lib/gitlab/import_export/decompressed_archive_size_validator.rb#L82 ```ruby       def command         "gzip -dc #{@archive_path} | wc -c"       end     def validate         pgrp = nil         valid_archive = true         ...
- [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/925585) -- PayPal | $30,000 | Code Injection | 943up
  > A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have...
- [Exposed Kubernetes API - RCE/Exposed Creds](https://hackerone.com/reports/455645) -- Snapchat | $25,000 | OS Command Injection | 1189up
  > @txt3rob found one of Snaps internal Kubernetes instances exposing an API endpoint without authorization to the public. With access to this API he was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances.
- [Potential pre-auth RCE on Twitter VPN](https://hackerone.com/reports/591295) -- X / xAI | $20,160 | OS Command Injection | 1245up
  > Thanks Twitter Security Team again :) The details can be found here! * [Attacking SSL VPN - Part 3: The Golden Pulse Secure SSL VPN RCE Chain, with Twitter as Case Study!](https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html)
- [[phpobject in cookie] Remote shell/command execution](https://hackerone.com/reports/141956) -- Pornhub | $20,000 | Code Injection | 607up
- [RCE when removing metadata with ExifTool](https://hackerone.com/reports/1154542) -- GitLab | $20,000 | Code Injection | 508up
  > ### Summary When uploading image files, GitLab Workhorse passes any files with the extensions [jpg|jpeg|tiff](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.10.2-ee/workhorse/internal/upload/exif/exif.go#L104) through to [ExifTool](https://exiftool.org/) to remove any non-whitelisted tags.  An issue with this is that ExifTool will ignore the file extension and try to determine what the file is...
- [RCE via unsafe inline Kramdown options when rendering certain Wiki pages](https://hackerone.com/reports/1125425) -- GitLab | $20,000 | Code Injection | 427up
  > ### Summary  When rendering wiki content with certain extensions such as `.rmd`,  `render_wiki_content` will call [`other_markup_unsafe`](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.9.3-ee/app/helpers/markup_helper.rb#L145) which will end up calling `GitHub::Markup.render` from the `github-markup` gem.  Files with any extension can be uploaded by checking out the wiki with git, commiting...
- [Oracle Webcenter Sites administrative and hi-privilege access available directly from the internet (/cs/Satellite)](https://hackerone.com/reports/170532) -- LocalTapiola | $18,000 | Uncontrolled Resource Consumption | 264up
- [Struct type confusion RCE](https://hackerone.com/reports/181879) -- shopify-scripts | $18,000 | Code Injection | 14up
  > Heya!  I've been poking at mruby a bit more and I've found a vulnerability that allows an attacker to take control of the instruction pointer.  I've attached a proof of concept script that when run in mruby will jump to `0x0000133713371337` and segfault.  While the proof of concept script just jumps to an attacker controlled address and crashes, it would almost certainly be possible to achieve...
- [Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application](https://hackerone.com/reports/873614) -- PlayStation | $15,000 | Code Injection | 779up
  > -
- [Git flag injection - local file overwrite to remote code execution](https://hackerone.com/reports/658013) -- GitLab | $12,000 | Command Injection - Generic | 777up
  > ### Summary  The `wiki_blobs` scope of the Search API can be provided with an arbitrary `ref` parameter, allowing for additional flags to be injected into the git command.   For example the following API call:  ``` `curl --header "PRIVATE-TOKEN: $TOKEN" 'http://gitlab-vm.local/api/v4/projects/4/search?scope=wiki_blobs&search=page&ref=--output=/tmp/file'` ```  The above will generate the...
- [Local files could be overwritten in GitLab, leading to remote command execution](https://hackerone.com/reports/587854) -- GitLab | $12,000 | Command Injection - Generic | 542up
  > ### Summary #### Arbitrary file overwrite A new feature (download a directory of a repository) in GitLab 11.11 introduced some changes in `./internal/service/repository/archive.go` of Gitaly. ```go func handleArchive(ctx context.Context, writer io.Writer, in *gitalypb.GetArchiveRequest, compressCmd *exec.Cmd, format string, path string) error {                                                   ...
- [Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)](https://hackerone.com/reports/3782701) -- Mozilla | $12,000 | Code Injection | 355up
  > ## Summary  The public GraphQL endpoint at `/graphql` allows an unauthenticated caller to execute arbitrary JavaScript inside the web-server's Node.js process. The query argument `filter` is a free-form JSON object that the server passes directly into the `sift` library. The version in use (`sift` 17.1.3) compiles a `$where` string into a function using `new Function` and executes it.  Code...
- [Path traversal, to RCE](https://hackerone.com/reports/733072) -- GitLab | $12,000 | Command Injection - Generic | 142up
  > ### Summary This one is similar to #732330 but much simpler. A path traversal issue in GitLab package registry API allow an attacker to write any file at any location writable to user git in a GitLab server.  ### Steps to reproduce  1. Enable package registry in your GitLab instance. 2. Create a project (package registry is enabled by default) 3. Create a private token to call the API 4. Send...

---

- [Arbitrary Code Execution via npm misconfiguration – installing internal libraries from the public registry](https://hackerone.com/reports/1043385) -- LY Corporation | $11,500 | Code Injection | 288up
- [Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives](https://hackerone.com/reports/826026) -- PlayStation | $10,000 | Use After Free | 741up
- [RCE on shared.mail.ru due to "widget" plugin](https://hackerone.com/reports/518637) -- Mail.ru | $10,000 | Code Injection | 359up
- [Malformed NAV file leads to buffer overflow and code execution in Left4Dead2.exe](https://hackerone.com/reports/542180) -- Valve | $10,000 | Classic Buffer Overflow | 268up
- [sys_fsc2h_ctrl kernel stack free](https://hackerone.com/reports/2900606) -- PlayStation | $10,000 | Use After Free | 236up
- [Publicly exposed SVN repository, ht.pornhub.com](https://hackerone.com/reports/72243) -- Pornhub | $10,000 | Code Injection | 211up
- [Use-after-free in setsockopt IPV6_2292PKTOPTIONS (CVE-2020-7457)](https://hackerone.com/reports/1441103) -- PlayStation | $10,000 | Use After Free | 142up
- [uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980) -- Uber | $10,000 | Code Injection | 137up
- [RCE hazard in reporting (via Chromium)](https://hackerone.com/reports/1168765) -- Elastic | $10,000 | Privilege Escalation | 25up
- [Invalid handling of zero-length heredoc identifiers leads to infinite loop in the sandbox](https://hackerone.com/reports/187305) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 23up
- [Segfault and/or potential unwanted (byte)code execution with "break" and "--=" inside a loop](https://hackerone.com/reports/183356) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 14up
- [Buffer overflow in mrb_time_asctime](https://hackerone.com/reports/188326) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 13up
- [Broken handling of maximum number of method call arguments leads to segfault](https://hackerone.com/reports/182484) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 10up
- [Null pointer derefence due to bug in codegen with negation without using value](https://hackerone.com/reports/187536) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 9up
- [Range#initialize_copy null pointer dereference](https://hackerone.com/reports/181685) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 9up
- [Range constructor type confusion DoS](https://hackerone.com/reports/181910) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 7up
- [Segfault in mruby, mruby_engine and the parent MRI Ruby due to null pointer dereference](https://hackerone.com/reports/181828) -- shopify-scripts | $10,000 | Uncontrolled Resource Consumption | 4up
- [DoS on PayPal via web cache poisoning](https://hackerone.com/reports/622122) -- PayPal | $9,700 | Uncontrolled Resource Consumption | 851up
- [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/1007014) -- Uber | $9,000 | Code Injection | 325up
- [RCE on CS:GO client using unsanitized entity ID in EntityMsg message](https://hackerone.com/reports/584603) -- Valve | $9,000 | Out-of-bounds Read | 209up
- [Remote code execution and exfiltration of secret tokens by poisoning the mozilla/fxa CI build cache](https://hackerone.com/reports/2255750) -- Mozilla | $8,000 | Code Injection | 58up
- [Segmentation fault when a Ruby method is invoked by a C method via Object#send](https://hackerone.com/reports/183425) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 14up
- [Null target_class DoS](https://hackerone.com/reports/183405) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 14up
- [Denial of service due to invalid memory access in mrb_ary_concat](https://hackerone.com/reports/184712) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 9up
- [Denial of Service in mruby due to null pointer dereference](https://hackerone.com/reports/181232) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 8up
- [Undefined method_missing null pointer dereference](https://hackerone.com/reports/181695) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 7up
- [ruby DoS https://www.mruby.science](https://hackerone.com/reports/180695) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 5up
- [Segmentation fault due to bad memory access in kh_get_mt](https://hackerone.com/reports/188313) -- shopify-scripts | $8,000 | Uncontrolled Resource Consumption | 4up
- [DOS via issue preview](https://hackerone.com/reports/1543718) -- GitLab | $7,640 | Uncontrolled Resource Consumption | 25up
- [OOB reads in network message handlers leads to RCE](https://hackerone.com/reports/807772) -- Valve | $7,500 | Out-of-bounds Read | 219up
- [Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games](https://hackerone.com/reports/463286) -- Valve | $7,500 | Classic Buffer Overflow | 109up
- [CS:GO Server -> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download](https://hackerone.com/reports/1070835) -- Valve | $7,500 | Out-of-bounds Read | 66up
- [Signedness issue in ClassInfo message handler leads to RCE on CS:GO client](https://hackerone.com/reports/876719) -- Valve | $7,500 | Array Index Underflow | 35up
- [Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com/graphql](https://hackerone.com/reports/3694007) -- HackerOne | $7,000 | Code Injection | 169up
- [Git flag injection - Search API with scope 'blobs'](https://hackerone.com/reports/682442) -- GitLab | $7,000 | Command Injection - Generic | 130up
- [OneLogin authentication bypass on WordPress sites via XMLRPC](https://hackerone.com/reports/138869) -- Uber | $7,000 | Code Injection | 83up
- [Mozilla VPN Clients: RCE via file write and path traversal](https://hackerone.com/reports/2995025) -- Mozilla | $6,000 | Path Traversal | 172up
- [Apache Flink RCE via GET jar/plan API Endpoint](https://hackerone.com/reports/1418891) -- Aiven Ltd | $6,000 | Command Injection - Generic | 134up
- [Remote code execution on Basecamp.com](https://hackerone.com/reports/365271) -- Basecamp | $5,000 | Command Injection - Generic | 416up
- [[Portal 2] Remote Code Execution via voice packets](https://hackerone.com/reports/733267) -- Valve | $5,000 | Classic Buffer Overflow | 173up
- [DOS of RSKJ server](https://hackerone.com/reports/2105808) -- Rootstock Labs | $5,000 | Uncontrolled Resource Consumption | 120up
- [Insecure Bundler configuration fetching internal Gems (okra) from Rubygems.org](https://hackerone.com/reports/1104874) -- Basecamp | $5,000 | Command Injection - Generic | 102up
- [Unsecured DB instance](https://hackerone.com/reports/189192) -- Pornhub | $5,000 | Code Injection | 73up
- [Grafana RCE via SMTP server parameter injection](https://hackerone.com/reports/1200647) -- Aiven Ltd | $5,000 | CRLF Injection | 72up
- [CVE-2023-5528: Insufficient input sanitization in in-tree storage plugin leads to privilege escalation on Windows nodes](https://hackerone.com/reports/2231019) -- Kubernetes | $5,000 | Code Injection | 67up
- [[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia](https://hackerone.com/reports/1547877) -- Aiven Ltd | $5,000 | Unrestricted Upload of File with Dangerous Type | 56up
- [Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration](https://hackerone.com/reports/1529790) -- Aiven Ltd | $5,000 | Deserialization of Untrusted Data | 45up
- [Augur UI data can be completely replaced by an attacker which can lead to fund and reputation loss](https://hackerone.com/reports/386587) -- Augur | $5,000 | Client-Side Enforcement of Server-Side Security | 40up
- [Possibility to brute force invite codes in riders.uber.com](https://hackerone.com/reports/125505) -- Uber | $5,000 | Violation of Secure Design Principles | 35up
- [Remote Code Execution in coming Kibana 7.7.0](https://hackerone.com/reports/861744) -- Elastic | $5,000 | Privilege Escalation | 14up
- [Unauthenticated access to Content Management System - www1.pornhubpremium.com](https://hackerone.com/reports/72735) -- Pornhub | $5,000 | Command Injection - Generic | 7up
- [Adobe Flash Player Regular Expression UAF Remote Code Execution Vulnerability](https://hackerone.com/reports/139879) -- Internet Bug Bounty | $5,000 | Memory Corruption - Generic | 1up
- [CVE-2024-34750 Apache Tomcat DoS vulnerability in HTTP/2 connector](https://hackerone.com/reports/2586226) -- Internet Bug Bounty | $4,920 | Uncontrolled Resource Consumption | 60up
- [CVE-2024-27281: RCE vulnerability with .rdoc_options in RDoc](https://hackerone.com/reports/2438265) -- Internet Bug Bounty | $4,860 | 87up
- [Denial of Service caused by HTTP/2 CONTINUATION Flood](https://hackerone.com/reports/2334401) -- Internet Bug Bounty | $4,860 | Uncontrolled Resource Consumption | 42up
- [C/C++: Command injection via wordexp](https://hackerone.com/reports/1738940) -- GitHub Security Lab | $4,500 | 5up
- [CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet](https://hackerone.com/reports/3031518) -- Internet Bug Bounty | $4,323 | Deserialization of Untrusted Data | 56up
- [Admin Panel Accessed (OAuth Bypassed )](https://hackerone.com/reports/294911) -- Mapbox | $4,000 | Command Injection - Generic | 133up
- [CVE-2022-40127: RCE in Apache Airflow <2.4.0 bash example](https://hackerone.com/reports/1776476) -- Internet Bug Bounty | $4,000 | Code Injection | 60up
- [DoS via markdown API from unauthenticated user](https://hackerone.com/reports/1619604) -- GitHub | $4,000 | Uncontrolled Resource Consumption | 54up
- [ReDoS( Ruby, Time)](https://hackerone.com/reports/1929567) -- Internet Bug Bounty | $4,000 | Uncontrolled Resource Consumption | 51up
- [DoS through PeerExplorer](https://hackerone.com/reports/363636) -- Rootstock Labs | $4,000 | Uncontrolled Resource Consumption | 50up
- [Command injection in GitHub Actions ContainerStepHost](https://hackerone.com/reports/1637621) -- GitHub | $4,000 | Resource Injection | 32up
- [Regexes with large repetitions on empty sub-expressions take a very long time to parse](https://hackerone.com/reports/1518036) -- Internet Bug Bounty | $4,000 | Uncontrolled Resource Consumption | 25up
- [Assertion failed in node::http2::Http2Session::~Http2Session() leads to HTTP/2 server crash](https://hackerone.com/reports/2453328) -- Internet Bug Bounty | $3,645 | Uncontrolled Resource Consumption | 39up
- [Git flag injection leading to file overwrite and potential remote code execution](https://hackerone.com/reports/653125) -- GitLab | $3,500 | Command Injection - Generic | 169up
- [http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks](https://hackerone.com/reports/2375446) -- Internet Bug Bounty | $3,495 | Uncontrolled Resource Consumption | 40up
- [[h1-2102] FQDN takeover on all Shopify wholesale customer domains by trailing dot (RFC 1034)](https://hackerone.com/reports/1086108) -- Shopify | $3,100 | Incorrect Permission Assignment for Critical Resource | 166up
- [Unrestricted file upload on [ambassador.mail.ru]](https://hackerone.com/reports/854032) -- Mail.ru | $3,000 | Code Injection | 404up
- [Unchecked weapon id in WeaponList message parser on client leads to RCE](https://hackerone.com/reports/513154) -- Valve | $3,000 | Array Index Underflow | 229up
- [RCE of Burp  Scanner / Crawler via Clickjacking](https://hackerone.com/reports/1274695) -- PortSwigger Web Security | $3,000 | Command Injection - Generic | 172up
- [DoS on the Issue page by exploiting Mermaid.](https://hackerone.com/reports/470067) -- GitLab | $3,000 | Uncontrolled Resource Consumption | 145up
- [PHP code injection at tz.mail.ru](https://hackerone.com/reports/798135) -- Mail.ru | $3,000 | Code Injection | 137up
- [Race Condition Enables Bypassing Verification Check](https://hackerone.com/reports/2110030) -- Tools for Humanity | $3,000 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | 95up
- [RCE via WikiCloth markdown rendering if the `rubyluabridge` gem is installed](https://hackerone.com/reports/1401444) -- GitLab | $3,000 | OS Command Injection | 50up
- [GoldSrc: Buffer Overflow in DELTA_ParseDelta function leads to RCE](https://hackerone.com/reports/484745) -- Valve | $3,000 | Stack Overflow | 26up
- [Possibility to enumerate and bruteforce promotion codes in Uber iOS App](https://hackerone.com/reports/125707) -- Uber | $3,000 | Improper Restriction of Authentication Attempts | 24up
- [https://themes.shopify.com::: Host header web cache poisoning lead to DoS](https://hackerone.com/reports/1096609) -- Shopify | $2,900 | Uncontrolled Resource Consumption | 82up
- [Apache HTTP Server: HTTP/2 DoS by memory exhaustion on endless continuation frames](https://hackerone.com/reports/2453322) -- Internet Bug Bounty | $2,580 | Uncontrolled Resource Consumption | 40up
- [CVE-2023-46695: Potential denial of service vulnerability in UsernameField on Windows](https://hackerone.com/reports/2258758) -- Internet Bug Bounty | $2,540 | Uncontrolled Resource Consumption | 28up
- [Denial of service via cache poisoning](https://hackerone.com/reports/409370) -- HackerOne | $2,500 | Uncontrolled Resource Consumption | 253up
- [Uploading large payload on domain instructions causes server-side DoS](https://hackerone.com/reports/887321) -- HackerOne | $2,500 | Uncontrolled Resource Consumption | 210up
- [Unauthorized user can obtain `report_sources` attribute through Team GraphQL object](https://hackerone.com/reports/770209) -- HackerOne | $2,500 | Information Disclosure | 142up
- [Program metrics disclosed response_efficiency_percentage via /program_name json response despite the team decided not to show on their profile](https://hackerone.com/reports/347693) -- HackerOne | $2,500 | Information Disclosure | 64up
- [[Source Engine] Material path truncation leads to Remote Code Execution](https://hackerone.com/reports/544096) -- Valve | $2,500 | Improper Input Validation | 60up