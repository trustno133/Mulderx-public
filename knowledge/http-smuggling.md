# HTTP Smuggling -- Top 73 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Bypass for #488147 enables stored XSS on https://paypal.com/signin again](https://hackerone.com/reports/510152) -- PayPal | $20,000 | HTTP Request Smuggling | 2686up
  > Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages,...
- [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) -- PayPal | $18,900 | HTTP Request Smuggling | 684up
  > Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages,...
- [HTTP Request Smuggling via HTTP/2](https://hackerone.com/reports/1211724) -- Basecamp | $7,500 | HTTP Request Smuggling | 298up
  > HTTP Request Smuggling via HTTP/2
- [HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function](https://hackerone.com/reports/1478633) -- Cloudflare Public Bug Bounty | $6,000 | HTTP Request Smuggling | 116up
  > The Edge Rules engine used by Cloudflare Transform Rules features string modifying functions like lower() and concat(), which accepted hexadecimal-encoded characters such as ”\x0a\x0d“. This allowed for manipulation of request headers (e.g. injecting an additional header) and, as a consequence, made HTTP smuggling attack (TE.CL) possible. This vulnerability enabled an attacker to bypass...
- [HTTP request smuggling (?) canpol.deti.mail.ru](https://hackerone.com/reports/957881) -- Mail.ru | $5,000 | 241up
- [Possibility of Request smuggling attack](https://hackerone.com/reports/2280391) -- Internet Bug Bounty | $4,660 | HTTP Request Smuggling | 93up
  > CVE-2023-46589 Apache Tomcat - Request Smuggling Severity: Important  Description: Tomcat did not correctly parse HTTP trailer headers. A specially crafted trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.  Credit: This vulnerability was reported...
- [CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)](https://hackerone.com/reports/2327341) -- Internet Bug Bounty | $4,660 | HTTP Request Smuggling | 57up
  > [SECURITY] CVE-2024-21733 Apache Tomcat - Information Disclosure Severity: Important Vendor: The Apache Software Foundation  Versions Affected: Apache Tomcat 9.0.0-M11 to 9.0.43 Apache Tomcat 8.5.7 to 8.5.63  Description: Incomplete POST requests triggered an error response that could contain data from a previous request from another user.  Mitigation: Users of the affected versions should...
- [Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)](https://hackerone.com/reports/2299692) -- Internet Bug Bounty | $4,660 | HTTP Request Smuggling | 51up
  > [SECURITY] CVE-2023-45648 Apache Tomcat - Request Smuggling Severity: Important Vendor: The Apache Software Foundation  Versions Affected: Apache Tomcat 11.0.0-M1 to 11.0.0-M11 Apache Tomcat 10.1.0-M1 to 10.1.13 Apache Tomcat 9.0.0-M1 to 9.0.80 Apache Tomcat 8.5.0 to 8.5.93  Description: Tomcat did not correctly parse HTTP trailer headers. A specially crafted, invalid trailer header could cause...
- [Pause-based desync in Apache HTTPD](https://hackerone.com/reports/1667974) -- Internet Bug Bounty | $4,000 | HTTP Request Smuggling | 73up
  > important: HTTP request smuggling vulnerability in Apache HTTP Server 2.4.52 and earlier (CVE-2022-22720)  Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling  Acknowledgements: James Kettle <james.kettle portswigger.net>  Reported to security team:	2021-12-17 fixed by...
- [HTTP request smuggling with Origin Rules using newlines in the host_header action parameter](https://hackerone.com/reports/1575912) -- Cloudflare Public Bug Bounty | $3,100 | HTTP Request Smuggling | 46up
  > The `host_header` action parameter available to rulesets in the [Origin Rules API](https://developers.cloudflare.com/rules/origin-rules/) lacked sufficient input validation i.e., allowing CRLF characters. Because of this, it was possible to inject arbitrary headers and, as a consequence, smuggle HTTP requests. This vulnerability enabled bypassing security products such as Cloudflare Access and...
- [Password theft login.newrelic.com via Request Smuggling](https://hackerone.com/reports/498052) -- New Relic | $3,000 | HTTP Request Smuggling | 490up
- [Apache HTTP Server: mod_proxy_ajp: Possible request smuggling](https://hackerone.com/reports/1594627) -- Internet Bug Bounty | $2,400 | 21up
  > moderate: mod_proxy_ajp: Possible request smuggling (CVE-2022-26377)  Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.  Acknowledgements:...
- [HTTP Request Smuggling via Empty headers separated by CR](https://hackerone.com/reports/2032842) -- Internet Bug Bounty | $1,800 | HTTP Request Smuggling | 16up
  > The llhttp parser in the http module in Node.js does not strictly use the CRLF sequence to delimit HTTP requests. This can lead to HTTP Request Smuggling (HRS).  The CR character (without LF) is sufficient to delimit HTTP header fields in the llhttp parser. According to RFC7230 section 3, only the CRLF sequence should delimit each header-field.  This vulnerability impacts all Node.js active...
- [HTTP Request Smuggling Due to Incorrect Parsing of Header Fields](https://hackerone.com/reports/1888760) -- Internet Bug Bounty | $1,800 | HTTP Request Smuggling | 15up
  > CVE-2022-35256 Detail  Description The llhttp parser in the http module in Node v18.7.0 does not correctly handle header fields that are not terminated with CLRF. This may result in HTTP Request Smuggling.  NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-35256 HackerOne original submission: https://hackerone.com/reports/1675191
- [CVE-2022-32213 - HTTP Request Smuggling Due to Flawed Parsing of Transfer-Encoding](https://hackerone.com/reports/1630668) -- Internet Bug Bounty | $1,800 | HTTP Request Smuggling | 13up
  > HTTP Request Smuggling - Flawed Parsing of Transfer-Encoding (Medium)(CVE-2022-32213)  The llhttp parser in the http module does not correctly parse and validate Transfer-Encoding headers. This can lead to HTTP Request Smuggling (HRS).  More details will be available at CVE-2022-32213 after publication.  Thank you to Zeyu Zhang (@zeyu2001) for reporting this vulnerability.  Impacts:  All...

---

- [CVE-2022-32214 - HTTP Request Smuggling Due To Improper Delimiting of Header Fields](https://hackerone.com/reports/1630669) -- Internet Bug Bounty | $1,800 | HTTP Request Smuggling | 11up
- [CVE-2022-32215 - HTTP Request Smuggling Due to Incorrect Parsing of Multi-line Transfer-Encoding](https://hackerone.com/reports/1630667) -- Internet Bug Bounty | $1,800 | HTTP Request Smuggling | 6up
- [HTTP Request Smuggling via Unsanitized Hop-by-Hop Headers](https://hackerone.com/reports/3622877) -- Cloudflare Public Bug Bounty | $1,500 | Improper Access Control - Generic | 51up
- [HTTP Request Smuggling on https://labs.data.gov](https://hackerone.com/reports/726773) -- GSA Bounty | $750 | HTTP Request Smuggling | 160up
- [http request smuggling in pscp.tv and periscope.tv](https://hackerone.com/reports/713285) -- X / xAI | $560 | HTTP Request Smuggling | 24up
- [HTTP Request Smuggling at app.workbox.dk](https://hackerone.com/reports/919988) -- Visma Public | $500 | HTTP Request Smuggling | 139up
- [HTTP Request Smuggling on vpn.lob.com](https://hackerone.com/reports/694604) -- Lob | $500 | HTTP Request Smuggling | 123up
- [Request Smuggling vulnerability due a vulnerable skipper reverse proxy running in the environment.](https://hackerone.com/reports/711679) -- Razer | $375 | 18up
- [Potential HTTP Request Smuggling in nodejs](https://hackerone.com/reports/1002188) -- Node.js | $250 | HTTP Request Smuggling | 34up
- [[spectacles.com] Bypassing quantity limit in orders](https://hackerone.com/reports/246803) -- Snapchat | $250 | HTTP Request Smuggling | 22up
- [HTTP Request Smuggling due to accepting space before colon](https://hackerone.com/reports/1238709) -- Node.js | $250 | HTTP Request Smuggling | 18up
- [HTTP Request Smuggling due to ignoring chunk extensions](https://hackerone.com/reports/1238099) -- Node.js | $250 | HTTP Request Smuggling | 7up
- [Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies](https://hackerone.com/reports/737140) -- Slack | HTTP Request Smuggling | 868up
- [Request smuggling on admin-official.line.me could lead to account takeover](https://hackerone.com/reports/740037) -- LY Corporation | HTTP Request Smuggling | 564up
- [Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com](https://hackerone.com/reports/771666) -- Eternal | HTTP Request Smuggling | 559up
- [HTTP request Smuggling](https://hackerone.com/reports/867952) -- Helium | HTTP Request Smuggling | 300up
- [HTTP Request Smuggling due to CR-to-Hyphen conversion](https://hackerone.com/reports/922597) -- Node.js | HTTP Request Smuggling | 134up
- [Improper HTTP header block termination in llhttp](https://hackerone.com/reports/2054283) -- Node.js | HTTP Request Smuggling | 122up
- [HTTP request smuggling using malformed Transfer-Encoding header](https://hackerone.com/reports/735748) -- Node.js | HTTP Request Smuggling | 105up
- [HTTP Smuggling multiple issues in Squid 3.x & squid 4.x](https://hackerone.com/reports/758445) -- Internet Bug Bounty | HTTP Response Splitting | 74up
- [HTTP SMUGGLING EXPOSED HMAC/DOS](https://hackerone.com/reports/753939) -- Magic | HTTP Request Smuggling | 74up
- [Potential HTTP Request Smuggling in ruby webrick](https://hackerone.com/reports/965267) -- Ruby | HTTP Request Smuggling | 53up
- [HTTP Request Smuggling via Connection: close<TAB> in Node.js llhttp parser](https://hackerone.com/reports/3723248) -- Node.js | HTTP Request Smuggling | 49up
- [HTTP Request Smuggling](https://hackerone.com/reports/1120982) -- U.S. Dept Of Defense | HTTP Request Smuggling | 40up
- [HTTP/1.1 Response Desynchronization via conflicting CL/TE headers in Proxy CONNECT](https://hackerone.com/reports/3623064) -- curl | HTTP Request Smuggling | 30up
- [Improper Input Validation — HTTP Response Parser Unconditionally Accepts Bare CR in Status Line](https://hackerone.com/reports/3648681) -- Node.js | HTTP Request Smuggling | 29up
- [HTTP Request Smuggling on api.flocktory.com Leads to XSS on Customer Sites](https://hackerone.com/reports/955170) -- QIWI | HTTP Request Smuggling | 29up
- [HTTP request smuggling on Basecamp 2 allows web cache poisoning](https://hackerone.com/reports/919175) -- Basecamp | HTTP Request Smuggling | 28up
- [Host Header Injection](https://hackerone.com/reports/1098948) -- Kartpay | HTTP Request Smuggling | 27up
- [HTTP/1.1 response framing violation and unsafe connection reuse when transfer decoding is disabled](https://hackerone.com/reports/4025056) -- curl | HTTP Request Smuggling | 26up
- [Unauthenticated request smuggling on launchpad.37signals.com](https://hackerone.com/reports/867577) -- Basecamp | HTTP Request Smuggling | 26up
- [Request smuggling on ████████](https://hackerone.com/reports/526880) -- U.S. Dept Of Defense | HTTP Request Smuggling | 25up
- [HTTP Request Smuggling Vulnerability Analysis - cURL Security Report](https://hackerone.com/reports/3249936) -- curl | HTTP Request Smuggling | 23up
- [Incomplete Suppression of  Transfer-Encoding: chunked Header in HTTP/2 After Redirect From HTTP/1.1](https://hackerone.com/reports/3793495) -- curl | HTTP Request Smuggling | 21up
- [Multiple HTTP Smuggling reports](https://hackerone.com/reports/648434) -- Internet Bug Bounty | HTTP Request Smuggling | 20up
- [Duplicate chunked Transfer-Encoding lets a malicious origin smuggle a response across reused HTTP proxy connections](https://hackerone.com/reports/3795615) -- curl | HTTP Request Smuggling | 18up
- [HTTP Request Smuggling via Content Length Obfuscation](https://hackerone.com/reports/2237099) -- Node.js | HTTP Request Smuggling | 18up
- [[demo.stripo.email] HTTP request Smuggling](https://hackerone.com/reports/1631228) -- Stripo Inc | HTTP Request Smuggling | 18up
- [http request smuggling in  twitter.com](https://hackerone.com/reports/715996) -- X / xAI | HTTP Request Smuggling | 17up
- [HTTP Request Smuggling via Silent Header Truncation in Node.js HTTP Parser](https://hackerone.com/reports/3564941) -- Node.js | HTTP Request Smuggling | 16up
- [HTTP Request Smuggling on https://consumer.acronis.com](https://hackerone.com/reports/1063627) -- Acronis | HTTP Request Smuggling | 16up
- [HTTP Request Smuggling on my.stripo.email](https://hackerone.com/reports/777651) -- Stripo Inc | 15up
- [HTTP Request Smuggling on https://promosandbox.acronis.com](https://hackerone.com/reports/1063493) -- Acronis | HTTP Request Smuggling | 12up
- [HTTP Request Smuggling](https://hackerone.com/reports/866382) -- Brave Software | HTTP Request Smuggling | 12up
- [Hackerone1](https://hackerone.com/reports/471087) -- RATELIMITED | HTTP Request Smuggling | 11up
- [Apache HTTP Request Parsing Whitespace Defects](https://hackerone.com/reports/244459) -- Internet Bug Bounty | HTTP Request Smuggling | 11up
- [HTTP Request Smuggling](https://hackerone.com/reports/643225) -- JamieWeb | HTTP Request Smuggling | 10up
- [HTTP Request Smuggling and SSRF via CRLF Injection in Curl_add_custom_headers](https://hackerone.com/reports/3484431) -- curl | HTTP Request Smuggling | 9up
- [HTTP Request Smuggling Due To Improper Delimiting of Header Fields](https://hackerone.com/reports/1524692) -- Node.js | HTTP Request Smuggling | 9up
- [HTTP Request Smuggling via Empty headers separated by CR](https://hackerone.com/reports/2001873) -- Node.js | HTTP Request Smuggling | 8up
- [Default behavior of Fastifys versioned routes can be used for cache poisoning when Fastify is used in combination with a http cache / CDN](https://hackerone.com/reports/1025575) -- Node.js third-party modules | HTTP Request Smuggling | 8up
- [HTTP Request Smuggling Due to Flawed Parsing of Transfer-Encoding](https://hackerone.com/reports/1524555) -- Node.js | HTTP Request Smuggling | 7up
- [HTTP Request Smuggling Due to Incorrect Parsing of Multi-line Transfer-Encoding](https://hackerone.com/reports/1501679) -- Node.js | HTTP Request Smuggling | 7up
- [HTTP Request Smuggling Due to Incorrect Parsing of Header Fields](https://hackerone.com/reports/1675191) -- Node.js | HTTP Request Smuggling | 6up
- [HTTP Request Smuggling Due to Incorrect Parsing of Multi-line Transfer-Encoding (improper fix for CVE-2022-32215)](https://hackerone.com/reports/1665156) -- Node.js | HTTP Request Smuggling | 6up
- [CVE-2022-32213 bypass via obs-fold mechanic](https://hackerone.com/reports/1630336) -- Node.js | HTTP Request Smuggling | 5up
- [HTTP Header Injection/HTTP_Response_Splitting](https://hackerone.com/reports/214436) -- Blockchain | HTTP Request Smuggling | 4up
- [Gratipay Website CSP "script-scr" includes "unsafe-inline"](https://hackerone.com/reports/231510) -- Gratipay | HTTP Request Smuggling | 1up