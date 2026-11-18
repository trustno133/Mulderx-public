# postMessage -- Top 27 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [XSS on any Shopify shop via abuse of the HTML5 structured clone algorithm in postMessage listener on "/:id/digital_wallets/dialog"](https://hackerone.com/reports/231053) -- Shopify | $3,000 | Cross-site Scripting (XSS) - DOM | 121up
  > This issue is a XSS affecting all Shopify stores that can be triggered via `windows.postMessage` from any remote origin. The report demonstrated a clever bypass of the escaping code we had in place to prevent code injection.
- [DOM Based XSS via postMessage at https://inventory.upserve.com/login/](https://hackerone.com/reports/603764) -- Upserve | $2,500 | Cross-site Scripting (XSS) - DOM | 171up
  > Due to incomplete origin validation, DOM-based XSS was possible at https://inventory.upserve.com/login/ when receiving a postMessage.
- [Read/Write arbitrary (non-HttpOnly) cookies on checkout pages via GoogleAnalyticsAdditionalScripts postMessage handler](https://hackerone.com/reports/1081167) -- Shopify | $1,600 | Cross-site Scripting (XSS) - Generic | 16up
  > # Background Shopify shops can be configured with a [Google Analytics integration](https://help.shopify.com/en/manual/reports-and-analytics/google-analytics) within the admin settings for a shop (`/admin/online_store/preferences`). This is a deeper integration than simply including `analytics.js` via a liquid template, for example [ecommerce...
- [Reflected XSS on transact.playstation.com using postMessage from the opening window](https://hackerone.com/reports/900619) -- PlayStation | $1,000 | Cross-site Scripting (XSS) - Reflected | 98up
  > ## Report Summary: When `transact.playstation.com` loads it handles messages received from `postMessage` in the `_receiveMessageFromTransactClientService` method. The only validation that is performed is to ensure that the referrer and origin match:  ```javascript _receiveMessageFromTransactClientService: function (e) {           var n = void 0,             r = this.get("replaceRoute"),        ...
- [Authorization Token on PlayStation Network Leaks via postMessage function](https://hackerone.com/reports/826394) -- PlayStation | $1,000 | Violation of Secure Design Principles | 74up
  > # Description After some analysis on how playstation network authentication work, I came across a certain pattern of how authorization tokens are handled. The web application utilizes postMessage function to exchange authorization tokens between windows/frames.  To simplify this, let's follow on one of authorization flows. When you enter, https://my.playstation.com There is a request...
- [DOM Based XSS in www.hackerone.com via PostMessage](https://hackerone.com/reports/398054) -- HackerOne | $500 | Cross-site Scripting (XSS) - DOM | 208up
  > **Summary:**  The Marketo contact form available on the www.hackerone.com website is affected by a cross-site scripting vulnerability, caused by an insecure 'message' event listener installed on the page. Whilst this could allow an attacker to execute JavaScript in the context of the www.hackerone.com application, there were some restrictions which reduced the overall risk presented by the...
- [H1514 DOM XSS on checkout.shopify.com via postMessage handler on /:id/sandbox/google_maps](https://hackerone.com/reports/423218) -- Shopify | $500 | Cross-site Scripting (XSS) - DOM | 46up
  > # Description: The `/:id/sandbox/google_maps` and `/:id/sandbox/google_autocomplete` routes on `checkout.shopify.com` are used to render the Google Map on the "Order Status" page as well as the address prediction on checkout pages. The page performs origin validation on incoming postMessages making sure the origin matches the shop associated with `:id` but then trusts all communication after...
- [Eval-based XSS in Game JS API (mailru.core.js) via cross-origin postMessage()](https://hackerone.com/reports/1071294) -- Mail.ru | $200 | Cross-site Scripting (XSS) - Generic | 12up
- [DOM based XSS via postMessage at store.my.games](https://hackerone.com/reports/1065776) -- Mail.ru | $200 | Cross-site Scripting (XSS) - DOM | 7up
- [Stealing contact form data on www.hackerone.com using Marketo Forms XSS with postMessage frame-jumping and jQuery-JSONP](https://hackerone.com/reports/207042) -- HackerOne | Violation of Secure Design Principles | 153up
  > Hi,  I just discovered that there's a scenario where the Marketo Forms solution being used on www.hackerone.com can actually be abused, using a few fun techniques, to trigger an XSS in the Cross-Origin-iframe being used by Marketo. This results in eavesdropping of the data being sent in the contact-form on www.hackerone.com.  What also made this nice on HackerOne was the auto-trigger to launch...
- [Stealing xoxs-tokens using weak postMessage / call-popup redirect to current team domain](https://hackerone.com/reports/207170) -- Slack | Violation of Secure Design Principles | 120up
  > @fransrosen discovered a vulnerability which would allow an attacker running a malicious site to steal XOXS tokens. We resolved the postMessage and call-popup redirect issues, and performed a thorough investigation to confirm that this had never been exploited. Thanks @fransrosen for an interesting finding!
- [DOM Based XSS in www.hackerone.com via PostMessage (bypass of #398054)](https://hackerone.com/reports/499030) -- HackerOne | Cross-site Scripting (XSS) - DOM | 106up
  > **Summary**  The security fix by Marketo to resolve the issue reported by @adac95 in #398054 can be bypassed by purchasing an .ma domain for €60.  **Description**  The issues described by @adac95 in #398054 remain insufficiently resolved because of an inadequate security check by Marketo in the following piece of JavaScript in `forms2.min.js` ```javascript if (a.originalEvent &&...
- [DOM XSS on multiple Automattic domains through postMessages](https://hackerone.com/reports/2371019) -- Automattic | Cross-site Scripting (XSS) - DOM | 92up
  > Hi Automattic team,  I have found a 2 flaws that when combined lead to DOM XSS on every website that is using Jetpack with the [Likes](https://jetpack.com/support/likes/) feature enabled.   The 2 flaws are respectively:  - A DOM XSS vulnerability on https://widgets.wp.com/sharing-buttons-preview/ - The Jetpack plugin creates a postMessage listener allowing messages from the "widgets.wp.com"...
- [1 Click to 'Close Account and Refund' via POSTMESSAGE](https://hackerone.com/reports/1897443) -- TikTok | Improper Access Control - Generic | 81up
  > A TikTok Ads endpoint sending postmessage sends POST requests without proper checks on the origin. This could have resulted in a cross-site request forgery (CSRF) being used to force another user to send a POST request with any parameters to any end point. This could have been used to close other parties' Ads account. We thank @sinayeganeh for reporting this to our team.
- [TikTok's pixel/sdk.js leaks current URL from websites using postMessage](https://hackerone.com/reports/1598749) -- TikTok | Improper Authorization | 79up
  > A vulnerability was found where an oauth token could have been leaked due to an origin check bypass in the TikTok Pixel SDK. We thank @fransrosen for reporting this to our team.

---

- [XSS via /api/v1/chat.postMessage](https://hackerone.com/reports/219957) -- Rocket.Chat | Cross-site Scripting (XSS) - Stored | 73up
- [xss due to incorrect handling of postmessages](https://hackerone.com/reports/1758132) -- Khan Academy | Cross-site Scripting (XSS) - DOM | 35up
- [[XSS] postMessage в jsapi/button](https://hackerone.com/reports/503707) -- Mail.ru | Cross-site Scripting (XSS) - DOM | 33up
- [User session access due to Oauth whitelist host bypass and postMessage](https://hackerone.com/reports/875938) -- Mail.ru | Cross-Site Request Forgery (CSRF) | 31up
- [Stored XSS with CRLF injection via post message to user feed](https://hackerone.com/reports/263191) -- Rockstar Games | Cross-site Scripting (XSS) - Stored | 19up
- [XSS on https://account.mail.ru/login via postMessage](https://hackerone.com/reports/269349) -- Mail.ru | Cross-site Scripting (XSS) - DOM | 18up
- [[javascript] CWE-020: CodeQL query to detect missing origin validation in cross-origin communication via postMessage](https://hackerone.com/reports/920285) -- GitHub Security Lab | 16up
- [Bypass to postMessage origin validation via FTP](https://hackerone.com/reports/210654) -- Slack | Cross-site Scripting (XSS) - Generic | 15up
- [XSS on https://o2.mail.ru/jsapi/button via PostMessage](https://hackerone.com/reports/868570) -- Mail.ru | Cross-site Scripting (XSS) - DOM | 9up
- [[reveal.js] XSS by calling arbitrary method via postMessage](https://hackerone.com/reports/691977) -- Node.js third-party modules | Cross-site Scripting (XSS) - DOM | 7up
- [XSS on e.mail.ru via postMessage](https://hackerone.com/reports/301794) -- Mail.ru | Cross-site Scripting (XSS) - DOM | 7up
- [xss on polaris.shopify.com/demo using postMessage](https://hackerone.com/reports/894518) -- Shopify | Cross-site Scripting (XSS) - DOM | 5up