# WebSocket -- Top 28 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [[uchat.uberinternals.com] Mattermost doesn't check Origin in Websockets, which leads to the Critical Inforamation Leakage.](https://hackerone.com/reports/201326) -- Uber | $2,000 | Cross-Site Request Forgery (CSRF) | 50up
  > Thanks for the report and participation in our program, @kxyry!
- [Initial websocket support for Javascript (SockJS)](https://hackerone.com/reports/854439) -- GitHub Security Lab | $1,800 | 67up
- [Lack or Origin check leads to Cross-Site Websocket Hijacking (CSWSH)](https://hackerone.com/reports/535436) -- Superhuman (formerly Grammarly) | $800 | Improper Access Control - Generic | 134up
  > # Summary  @fisher discovered a CSRF-related vulnerability in Coda docs by which an attacked could craft a convincing page that would make modifications to a specific document without the victim knowing. This is due to the inherent nature of Websockets not being secure by default. Although a fully-working proof of concept was not provided, the Coda security team swiftly patched the...
- [Posts sent via websockets aren't sanitized properly](https://hackerone.com/reports/2541027) -- Mattermost | $150 | Improper Input Validation | 40up
  > Posts aren't sanitized the same way when sent via Websockets as they are when saved to the database.   ## Example 1 - Permalink embed with fully customizable content ### Code ```javascript const MM_INSTANCE_URL = process.env.MM_INSTANCE_URL; const MM_AUTH_TOKEN = process.env.MM_AUTH_TOKEN; const MM_USER_ID = process.env.MM_USER_ID; const MM_CHANNEL_ID = process.env.MM_CHANNEL_ID; // the ID of...
- [`socket` command allows sending data over WebSockets to arbitrary origins from Grammarly Extension](https://hackerone.com/reports/395729) -- Superhuman (formerly Grammarly) | 140up
  > ## Summary  1. Attacker could trigger Grammarly extension's `socket` command using a crafted page to perform WS connection(and data sending) from extension's background page (with cookies and origin) to any URL. 2. Additionally, commands received from the attacker's server are handled by extension and could be used to trigger wrong business-logic behavior (misleading commands) or possibly(!)...
- [Exposed trip_no in WebSocket Responses Leading to Excessive information Disclosure](https://hackerone.com/reports/2209750) -- Bykea | Improper Access Control - Generic | 64up
  > @mrrhacker discovered a vulnerability in Bykea’s WebSocket implementation where trip_no was exposed to drivers before a bid was accepted. This identifier could be used to access customer tracking URLs, revealing excessive information of the customers to unauthorised drivers. The issue was resolved by masking sensitive identifiers in WebSocket responses and introducing hashing in tracking URLs...
- [CVE-2025-5399: WebSocket endless loop](https://hackerone.com/reports/3168039) -- curl | Loop with Unreachable Exit Condition ('Infinite Loop') | 57up
  > The function `curl_ws_send()` in libcurl on commit [12d13b84fa40aa657b83d5458944dbd9b978fb7e](https://github.com/curl/curl/blob/12d13b84fa40aa657b83d5458944dbd9b978fb7e/lib/ws.c) contains an infinite loop that can be triggered by a malicious server under specific circumstances. If an application uses `curl_ws_recv()` and `curl_ws_send()` to communicate with a websocket server, a malicious...
- [Buffer Overflow Vulnerability in WebSocket Handling](https://hackerone.com/reports/2298307) -- curl | Heap Overflow | 38up
  > ## Summary: Hello security team, Hope you are doing well :)  I would like to report a potential security vulnerability in the WebSocket handling code of the curl library. The issue is related to the usage of the `strcpy` function, which can lead to a buffer overflow if the length of the input is not properly checked. The vulnerable code snippet is located at [this...
- [curl Missing Sec-WebSocket-Accept Verification Enables MITM WebSocket Session Hijacking](https://hackerone.com/reports/3917775) -- curl | Man-in-the-Middle | 37up
  > ## Summary  curl's `Curl_ws_accept()` function in `lib/ws.c` processes the 101 Switching Protocols response to a client WebSocket upgrade request. RFC 6455 Section 4.1 mandates that the client MUST verify the `Sec-WebSocket-Accept` response header by computing the SHA-1 hash of the concatenation of the `Sec-WebSocket-Key` value with the magic GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`,...
- [WebSocket Fragmentation DoS on Curl Client](https://hackerone.com/reports/3303765) -- curl | Uncontrolled Resource Consumption | 32up
  > ### Summary A malicious WebSocket server can send a fragmented message (FIN=0) followed by a flood of continuation frames, causing the client (curl) to continuously allocate memory while waiting for message completion. This can result in high memory usage and potential crash (OOM), representing a Denial-of-Service vulnerability.  ---  ### Description The vulnerability occurs because curl does...
- [CVE-2025-10148: predictable WebSocket mask](https://hackerone.com/reports/3330839) -- curl | Reusing a Nonce, Key Pair in Encryption | 30up
  > No AI was involved.  ## Summary: The curl WebSocket implementation generates a fixed masking key at the beginning of a connection an re-uses it for every frame: * Generation of masking key `enc.mask` in `Curl_ws_accept`: https://github.com/curl/curl/blob/455afa1de5182b95a5dcc988f18cdff584b95239/lib/ws.c#L1340 * Usage in `ws_enc_write_head`:...
- [[socket.io] Cross-Site Websocket Hijacking](https://hackerone.com/reports/931197) -- Node.js third-party modules | Cross-Site Request Forgery (CSRF) | 27up
  > -
- [Staff with no permissions can listen to Shopify Ping conversations by registering to its different WebSocket Events](https://hackerone.com/reports/1023669) -- Shopify | Information Disclosure | 25up
  > By registering to a few different Shopify Ping Websocket Events on the `wss://argus.shopifycloud.com/graphql?shop_id={id}` endpoint, a staff without any permission can listen to conversions with customers.  ## Steps to reproduce 1. With a staff that doesn't have any permissions, login into the shop admin at `https://{shop}.myshopify.com/admin` 1. Within your browser, open the Network inspection...
- [Insecure WebSocket Usage in curl Documentation and Examples (CWE-319: Cleartext Transmission of Sensitive Information)](https://hackerone.com/reports/3295652) -- curl | Cleartext Transmission of Sensitive Information | 19up
  > The curl source repository contains official documentation and example code that demonstrate WebSocket connections using the insecure ws:// protocol instead of the secure wss://. This misleading guidance may encourage developers to implement cleartext WebSocket endpoints, exposing users and infrastructure to eavesdropping, MITM (Man-in-the-Middle) attacks, and session hijacking. Failing to...
- [GraphQL introspection query works through unauthenticated WebSocket](https://hackerone.com/reports/862835) -- Nuri | Misconfiguration | 17up
  > ## Summary: It is possible to execute GraphQL introspection query through unauthenticated WebSocket connection. PoC included.  ## Steps To Reproduce: To simplify reproducing I provided a simple html PoC file.    1. Start python static http server in directory with poc file: `python3 -m http.server` (this step is required to bypass CORS restrictions for opening local file in the browser)   1....

---

- [Buffer Overflow in WebSocket Handshake (lib/ws.c:1287)](https://hackerone.com/reports/3392174) -- curl | Classic Buffer Overflow | 16up
- [Cross-Site WebSocket Hijacking Lead to Steal XSRF-TOKEN](https://hackerone.com/reports/915541) -- Stripo Inc | Improper Access Control - Generic | 13up
- [libcurl WebSocket handshake accepts any Sec-WebSocket-Accept](https://hackerone.com/reports/3474865) -- curl | 10up
- [WebSocket Logic Error: Control Frame (PING/PONG) Starvation causes Connection Drop (DoS) during large transfers](https://hackerone.com/reports/3480039) -- curl | Business Logic Errors | 9up
- [User Information sent to client through websockets](https://hackerone.com/reports/163464) -- Legal Robot | Information Disclosure | 9up
- [CVE-2026-11586: WS Auto-PONG memory exhaustion](https://hackerone.com/reports/3788931) -- curl | Allocation of Resources Without Limits or Throttling | 6up
- [bypassing dashboard without account + Information disclosure trough websockets](https://hackerone.com/reports/1102780) -- Nextcloud | Improper Access Control - Generic | 6up
- [Controllable read beyond bounds in lua_websocket_readbytes() [zhbug_httpd_126]](https://hackerone.com/reports/1595290) -- Internet Bug Bounty | Information Disclosure | 5up
- [Cross Site WebSocket Hijacking](https://hackerone.com/reports/211283) -- Legal Robot | Improper Authentication - Generic | 3up
- [cross site web socket hijacking](https://hackerone.com/reports/274324) -- Legal Robot | 2up
- [mod_lua: Crash in websockets PING handling](https://hackerone.com/reports/103991) -- Internet Bug Bounty | 2up
- [The websocket traffic is not secure enough](https://hackerone.com/reports/178990) -- Legal Robot | Cross-Site Request Forgery (CSRF) | 1up
- [User Information sent to client through websockets](https://hackerone.com/reports/168223) -- Instacart | Information Disclosure | 1up