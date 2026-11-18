# XSS -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_




- [Bypass for #488147 enables stored XSS on https://paypal.com/signin again](https://hackerone.com/reports/510152) -- PayPal | $20,000 | HTTP Request Smuggling | 2686up
  > Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages,...
- [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) -- PayPal | $18,900 | HTTP Request Smuggling | 684up
  > Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages,...
- [Stored XSS in markdown via the DesignReferenceFilter](https://hackerone.com/reports/1212067) -- GitLab | $16,000 | Cross-site Scripting (XSS) - Stored | 316up
  > ### Summary When rendering markdown, links to designs are parsed using the following `link_reference_pattern`:  https://gitlab.com/gitlab-org/gitlab/-/blob/v13.12.1-ee/app/models/design_management/design.rb#L168 ```ruby     def self.link_reference_pattern       @link_reference_pattern ||= begin         path_segment = %r{issues/#{Gitlab::Regex.issue}/designs}         ext =...
- [Stored XSS via Kroki diagram](https://hackerone.com/reports/1731349) -- GitLab | $13,950 | Cross-site Scripting (XSS) - Stored | 295up
  > ### Summary  If Kroki has been enabled, it's possible to craft a `pre` block so that arbitrary attributes can be injected into the resulting `img` tag.   The css selector for finding a valid node to convert into a kroki diagram checks for either `pre[lang="#{diagram_type}"] > code` or for `pre > code[lang="#{diagram_type}"]`, but the diagram type is then set using `node.parent['lang'] ||...
- [New /add_contacts /remove_contacts quick commands susseptible to XSS from Customer Contact firstname/lastname fields](https://hackerone.com/reports/1578400) -- GitLab | $13,950 | Cross-site Scripting (XSS) - Stored | 93up
  > ### Summary  In Gitlab 15.0.0 a new Customer Relations feature was added that allows us to use quick actions to find the contact we wish to select.  However, I noticed that if I set the contact's first name or last name to <script>alert(document.domain)</script> we can get the XSS to trigger when we are attempting to use the quick commands to add/remove a contact.  ### Steps to reproduce  1....
- [XSS at jamfpro.shopifycloud.com](https://hackerone.com/reports/1444682) -- Shopify | $9,400 | Cross-site Scripting (XSS) - Generic | 240up
  > On January 9th, 2022, @kannthu discovered that the instance of Jamf Pro running on `https://jamfpro.shopifycloud.com` has the old Swagger-UI exposed at `/classicapi/doc/`. It was possible for an attacker to craft a URL that could introduce an XSS payload to be ran in the application context.  Our engineers deployed a fix that removed access to this endpoint, mitigating this vulnerability.
- [XSS in steam react chat client](https://hackerone.com/reports/409850) -- Valve | $7,500 | Cross-site Scripting (XSS) - Stored | 496up
  > # 1. Background The Steam Chat client is a particularly interesting system to attack because it's built using a modern set of technologies with strong security characteristics.  It's built on React, which has some of the strongest security characteristics of any modern Javascript application framework, and avoids use of the unsafe `dangerously` family of functions well.  Content Security Policy...
- [Stored XSS in developer.uber.com](https://hackerone.com/reports/131450) -- Uber | $7,500 | Cross-site Scripting (XSS) - Generic | 223up
  > An attacker can make a series of requests to https://uber.readme.io/ that will result in permanent defacement/stored XSS of all the documentation pages on https://developer.uber.com/  I'm not entirely sure if this is in scope, but it could definitely have a major impact on developer.uber.com so I figure you'd like to know either way.    Reproduction steps:  Load...
- [Stored XSS on any page in most Uber domains](https://hackerone.com/reports/217739) -- Uber | $6,000 | Cross-site Scripting (XSS) - Stored | 107up
  > Due to two IDOR vulnerabilities in Tealium, it was possible to compromise an administrator’s account and inject arbitrary Javascript into `https://tags.tiqcdn.com/utag/uber/*`, which an attacker could leverage for a stored XSS attack on several Uber domains. Additionally, a Tealium user’s password and MFA were resettable by any user, allowing an attacker to take over the account and modify code...
- [Possibility to inject a malicious JavaScript code in any file on tags.tiqcdn.com results in a stored XSS on any page in most Uber domains](https://hackerone.com/reports/256152) -- Uber | $6,000 | Cross-site Scripting (XSS) - Stored | 51up
  > When creating new tags on Tealium, the application did not check that the user creating the tag had authorized as the same account they were creating a tag for. It was possible for an attacker to inject arbitrary content into a web page using the `utag.js` tag. Depending on how the victim implemented these tags, this could potentially allow for text injection, content injection, and HTML...
- [Stored XSS in SVG file as data: url](https://hackerone.com/reports/1276742) -- Shopify | $5,300 | Cross-site Scripting (XSS) - Stored | 152up
  > On July 24, 2021, @irisrumtub discovered it was possible to insert an XSS payload encoded in an SVG file by using `data:` url's in the admin's rich text editor. Our engineers deployed a fix that avoid converting the `data:` URL into a `blob:` URL, which impedes the exploitation of this vulnerability.
- [Stored XSS in /admin/product and /admin/collections](https://hackerone.com/reports/1147433) -- Shopify | $5,300 | Cross-site Scripting (XSS) - Stored | 75up
  > @ashketchum noticed that we changed our program policy to accept rich text editor-based XSS vulnerabilities and immediately got to testing. What they found was that an attacker could achieve stored XSS by putting a payload directly into the HTML editor and saving the contents, storing malicious code to be executed on subsequent page loads.
- [[accounts.reddit.com] Redirect parameter allows for XSS](https://hackerone.com/reports/1962645) -- Reddit | $5,000 | Cross-site Scripting (XSS) - Generic | 394up
  > ## Summary: Hello team! I was tampering with the dest parameter in accounts.reddit.com and found out it is vulnerable to Cross Site Scripting once the victim performs the log in.  ## Steps To Reproduce:   1. Enter to the following link: ```https://accounts.reddit.com/?dest=javascript:alert(document.domain)```   - If not signed in, the user will be promped to log in and after doing so XSS will...
- [HEY.com email stored XSS](https://hackerone.com/reports/982291) -- Basecamp | $5,000 | Cross-site Scripting (XSS) - Stored | 359up
  > An attacker can bypass the HEY.com HTML sanitizer and inject arbitrary unsafe HTML in emails.  To reproduce the bug you have to send raw HTML-formatted email. You can do it e.g. with the Sendmail tool on Linux.  Example email: ~~~~ plain From: jouko@klikki.fi To: jouko@hey.com Subject: HackerOne test MIME-Version: 1.0 Content-type:...
- [RichText parser vulnerability in scheduled posts allows XSS](https://hackerone.com/reports/1930763) -- Reddit | $5,000 | Cross-site Scripting (XSS) - Stored | 280up
  > Reddit's MarkDown parser wasn't filtering hyperlinks on server-side in scheduled post feature, which lets attacker to modify a request with normal hyperlink embeding a malicious link using javascript scheme

---

- [XSS in steam react chat client](https://hackerone.com/reports/409850) -- Valve | $7,500 | Cross-site Scripting (XSS) - Stored | 496up
- [Stored XSS in developer.uber.com](https://hackerone.com/reports/131450) -- Uber | $7,500 | Cross-site Scripting (XSS) - Generic | 223up
- [Stored XSS on any page in most Uber domains](https://hackerone.com/reports/217739) -- Uber | $6,000 | Cross-site Scripting (XSS) - Stored | 107up
- [Possibility to inject a malicious JavaScript code in any file on tags.tiqcdn.com results in a stored XSS on any page in most Uber domains](https://hackerone.com/reports/256152) -- Uber | $6,000 | Cross-site Scripting (XSS) - Stored | 51up
- [Stored XSS in SVG file as data: url](https://hackerone.com/reports/1276742) -- Shopify | $5,300 | Cross-site Scripting (XSS) - Stored | 152up
- [Stored XSS in /admin/product and /admin/collections](https://hackerone.com/reports/1147433) -- Shopify | $5,300 | Cross-site Scripting (XSS) - Stored | 75up
- [[accounts.reddit.com] Redirect parameter allows for XSS](https://hackerone.com/reports/1962645) -- Reddit | $5,000 | Cross-site Scripting (XSS) - Generic | 394up
- [HEY.com email stored XSS](https://hackerone.com/reports/982291) -- Basecamp | $5,000 | Cross-site Scripting (XSS) - Stored | 359up
- [RichText parser vulnerability in scheduled posts allows XSS](https://hackerone.com/reports/1930763) -- Reddit | $5,000 | Cross-site Scripting (XSS) - Stored | 280up
- [Cross application scripting via account.mail.ru](https://hackerone.com/reports/470380) -- Mail.ru | $5,000 | Cross-site Scripting (XSS) - Stored | 205up
- [Reflected XSS on Pangle Endpoint](https://hackerone.com/reports/2352968) -- TikTok | $5,000 | Cross-site Scripting (XSS) - Reflected | 196up
- [Markdown parsing issue enables insertion of malicious tags and event handlers](https://hackerone.com/reports/299728) -- HackerOne | $5,000 | Cross-site Scripting (XSS) - Stored | 184up
- [Reflected xss in https://sh.reddit.com](https://hackerone.com/reports/1549206) -- Reddit | $5,000 | Cross-site Scripting (XSS) - Reflected | 166up
- [XSS on $shop$.myshopify.com/admin/ and partners.shopify.com via whitelist bypass in SVG icon for sales channel applications](https://hackerone.com/reports/232174) -- Shopify | $5,000 | Cross-site Scripting (XSS) - Stored | 87up
- [Blind Stored XSS Against Lahitapiola Employees - Session and Information leakage](https://hackerone.com/reports/135154) -- LocalTapiola | $5,000 | Cross-site Scripting (XSS) - Generic | 70up
- [Stored XSS in markdown when redacting references](https://hackerone.com/reports/836649) -- GitLab | $5,000 | Cross-site Scripting (XSS) - Stored | 50up
- [Stored XSS on developer.uber.com via admin account compromise](https://hackerone.com/reports/152067) -- Uber | $5,000 | Cross-site Scripting (XSS) - Generic | 37up
- [Improperly validated fields allows injection of arbitrary HTML via spoofed React objects](https://hackerone.com/reports/49652) -- HackerOne | $5,000 | Cross-site Scripting (XSS) - Generic | 23up
- [Vulnerability with the way \ escaped characters in <http://danlec.com> style links are rendered](https://hackerone.com/reports/46072) -- HackerOne | $5,000 | Cross-site Scripting (XSS) - Generic | 21up
- [Stored XSS on newsroom.uber.com admin panel / Stream WordPress plugin](https://hackerone.com/reports/127948) -- Uber | $5,000 | Cross-site Scripting (XSS) - Generic | 18up
- [Markdown parsing issue enables insertion of malicious tags and event handlers](https://hackerone.com/reports/46916) -- HackerOne | $5,000 | Cross-site Scripting (XSS) - Generic | 16up
- [Stored XSS through PDF viewer](https://hackerone.com/reports/881557) -- Slack | $4,875 | Cross-site Scripting (XSS) - Stored | 76up
- [Persistent XSS in Note objects](https://hackerone.com/reports/508184) -- GitLab | $4,500 | Cross-site Scripting (XSS) - Stored | 139up
- [Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg](https://hackerone.com/reports/340431) -- Uber | $4,000 | Cleartext Transmission of Sensitive Information | 376up
- [SafeParamsHelper::safe_params is not so safe](https://hackerone.com/reports/946728) -- GitLab | $4,000 | Cross-site Scripting (XSS) - Reflected | 24up
- [Cross-site Scripting (XSS) - Stored in RDoc wiki pages](https://hackerone.com/reports/662287) -- GitLab | $3,500 | UI Redressing (Clickjacking) | 282up
- [Reflected XSS online-store-git.shopifycloud.com](https://hackerone.com/reports/1410459) -- Shopify | $3,500 | Cross-site Scripting (XSS) - Reflected | 98up
- [XSSI on refer.xoom.com allows stealing email addresses and posting to Twitter on behalf of victim](https://hackerone.com/reports/450796) -- PayPal | $3,500 | Cross-Site Request Forgery (CSRF) | 81up
- [Stored XSS in merge request pages](https://hackerone.com/reports/723307) -- GitLab | $3,500 | Cross-site Scripting (XSS) - Stored | 53up
- [Stored XSS in photos_user_map.gne](https://hackerone.com/reports/1534636) -- Flickr | $3,263 | Cross-site Scripting (XSS) - Stored | 54up
- [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049) -- Lark Technologies | $3,000 | Server-Side Request Forgery (SSRF) | 178up
- [[First 30] Stored XSS on login.uber.com/oauth/v2/authorize via redirect_uri parameter](https://hackerone.com/reports/392106) -- Uber | $3,000 | Cross-site Scripting (XSS) - Stored | 131up
- [Stored XSS in custom emoji](https://hackerone.com/reports/1198517) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 130up
- [XSS on any Shopify shop via abuse of the HTML5 structured clone algorithm in postMessage listener on "/:id/digital_wallets/dialog"](https://hackerone.com/reports/231053) -- Shopify | $3,000 | Cross-site Scripting (XSS) - DOM | 121up
- [XSS in request approvals](https://hackerone.com/reports/402658) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 96up
- [Reflected XSS on TikTok Website](https://hackerone.com/reports/1378413) -- TikTok | $3,000 | Cross-site Scripting (XSS) - Reflected | 88up
- [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1106238) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 58up
- [Stored XSS on auth.uber.com/oauth/v2/authorize via redirect_uri parameter leads to Account Takeover](https://hackerone.com/reports/397497) -- Uber | $3,000 | Cross-site Scripting (XSS) - Stored | 52up
- [Stored XSS on the job page](https://hackerone.com/reports/856554) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 50up
- [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1280002) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 48up
- [Blind Stored XSS Via Staff Name](https://hackerone.com/reports/948929) -- Shopify | $3,000 | Cross-site Scripting (XSS) - Stored | 45up
- [Stored XSS in Brower `name` field reflected in two pages](https://hackerone.com/reports/348076) -- New Relic | $3,000 | Cross-site Scripting (XSS) - Stored | 39up
- [Stored XSS on issue comments and other pages which contain notes](https://hackerone.com/reports/1398305) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 38up
- [Reflected XSS on developer.uber.com via Angular template injection](https://hackerone.com/reports/125027) -- Uber | $3,000 | Cross-site Scripting (XSS) - Generic | 35up
- [Bypass Filter and get Stored Xss](https://hackerone.com/reports/299424) -- Shopify | $3,000 | Cross-site Scripting (XSS) - Stored | 34up
- [Reflected XSS POST method at partners.uber.com](https://hackerone.com/reports/129582) -- Uber | $3,000 | Cross-site Scripting (XSS) - Reflected | 31up
- [Stored DOM XSS via Mermaid chart](https://hackerone.com/reports/1103258) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 27up
- [Stored XSS on PyPi simple API endpoint](https://hackerone.com/reports/856836) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 25up
- [Reflected XSS via Unvalidated / Open Redirect in uber.com](https://hackerone.com/reports/125791) -- Uber | $3,000 | 11up
- [XSS in getrush.uber.com](https://hackerone.com/reports/125112) -- Uber | $3,000 | Cross-site Scripting (XSS) - Generic | 6up
- [Stored XSS in archive.uber.com Due to Injection of Javascript:alert(0)](https://hackerone.com/reports/126906) -- Uber | $3,000 | Cross-site Scripting (XSS) - Generic | 5up
- [Wrong Handling of Content-Type allows Flash injection and Rosseta flash patch bypass](https://hackerone.com/reports/78158) -- Internet Bug Bounty | $3,000 | Cross-site Scripting (XSS) - Generic | 1up
- [Xss triggered in Your-store.myshopify.com/admin/apps/shopify-email/editor/****](https://hackerone.com/reports/1472471) -- Shopify | $2,900 | Cross-site Scripting (XSS) - Stored | 63up
- [[CVE-2024-32464] ActionText ContentAttachment’s can Contain Unsanitized HTML](https://hackerone.com/reports/2542806) -- Internet Bug Bounty | $2,600 | Cross-site Scripting (XSS) - Stored | 32up
- [DOM Based XSS via postMessage at https://inventory.upserve.com/login/](https://hackerone.com/reports/603764) -- Upserve | $2,500 | Cross-site Scripting (XSS) - DOM | 171up
- [IE only: stored Cross-Site Scripting (XSS) vulnerability through Program Asset identifier](https://hackerone.com/reports/449351) -- HackerOne | $2,500 | Cross-site Scripting (XSS) - Stored | 156up
- [DOM XSS on ads.tiktok.com](https://hackerone.com/reports/1549451) -- TikTok | $2,500 | Cross-site Scripting (XSS) - DOM | 104up
- [Stored XSS in "Create Groups"](https://hackerone.com/reports/647130) -- GitLab | $2,500 | Cross-site Scripting (XSS) - Stored | 88up
- [(Prerelease UI) Stored XSS via role name in JSON chart](https://hackerone.com/reports/520630) -- New Relic | $2,500 | Cross-site Scripting (XSS) - Stored | 49up
- [Stored XSS via "my recent queries" selector in NRQL dashboard builder](https://hackerone.com/reports/626082) -- New Relic | $2,500 | Cross-site Scripting (XSS) - Stored | 15up
- [CSRF possible when SOP Bypass/UXSS is available](https://hackerone.com/reports/103787) -- HackerOne | $2,500 | Cross-Site Request Forgery (CSRF) | 11up
- [Stored XSS Via NRQL chartbuilder JSON view](https://hackerone.com/reports/634692) -- New Relic | $2,500 | Cross-site Scripting (XSS) - Stored | 9up
- [Malicious Node JavaScript Injection Leading to Theft of Private Keys and User Funds](https://hackerone.com/reports/666062) -- MyEtherWallet | $2,500 | Code Injection | 9up
- [Rails ActionView sanitize helper bypass leading to XSS using SVG tag.](https://hackerone.com/reports/1805873) -- Internet Bug Bounty | $2,400 | Cross-site Scripting (XSS) - Generic | 40up
- [CVE-2022-23519: Rails::Html::SafeListSanitizer vulnerable to XSS when certain tags are allowed (math+style -- svg+style)](https://hackerone.com/reports/1805899) -- Internet Bug Bounty | $2,400 | Cross-site Scripting (XSS) - Generic | 22up
- [CVE-2022-23520: Incomplete fix for CVE-2022-32209 (XSS in Rails::Html::Sanitizer under certain configurations)](https://hackerone.com/reports/1805893) -- Internet Bug Bounty | $2,400 | Cross-site Scripting (XSS) - Generic | 15up
- [Rails::Html::SafeListSanitizer vulnerable to xss attack in an environment that allows the style tag](https://hackerone.com/reports/1599573) -- Internet Bug Bounty | $2,400 | Cross-site Scripting (XSS) - Generic | 12up
- [Stored XSS via malicious key value of Synthetics monitor tag when visiting an Insights dashboard with filtering enabled](https://hackerone.com/reports/1067321) -- New Relic | $2,123 | Cross-site Scripting (XSS) - Stored | 86up
- [Cross-site scripting on algorithm collaborator](https://hackerone.com/reports/615672) -- Quantopian | $2,100 | Cross-site Scripting (XSS) - Stored | 37up
- [Possible XSS vulnerability without a content security bypass](https://hackerone.com/reports/1804177) -- Stripe | $2,000 | Cross-site Scripting (XSS) - Generic | 131up
- [Reflective Cross-site Scripting via Newsletter Form](https://hackerone.com/reports/709336) -- Shopify | $2,000 | Cross-site Scripting (XSS) - Reflected | 79up
- [Stored XSS on activity](https://hackerone.com/reports/391390) -- Shopify | $2,000 | Cross-site Scripting (XSS) - Stored | 55up
- [XSS vulnerability without a content security bypass in a `CUSTOM` App through Button tag](https://hackerone.com/reports/1823216) -- Stripe | $2,000 | Cross-site Scripting (XSS) - Generic | 46up
- [Reflected XSS on multiple uberinternal.com domains](https://hackerone.com/reports/326449) -- Uber | $2,000 | Cross-site Scripting (XSS) - Reflected | 41up
- [Tinymce 2.4.0](https://hackerone.com/reports/262230) -- Shopify | $2,000 | Cross-site Scripting (XSS) - DOM | 37up
- [Reflected XSS on Partners Subdomain](https://hackerone.com/reports/390181) -- Uber | $2,000 | 31up
- [Stored XSS in repository file viewer](https://hackerone.com/reports/1072868) -- GitLab | $2,000 | Cross-site Scripting (XSS) - Stored | 29up
- [Stored XSS in group issue list](https://hackerone.com/reports/859333) -- GitLab | $2,000 | Cross-site Scripting (XSS) - Stored | 27up
- [XSS in ubermovement.com via editable Google Sheets](https://hackerone.com/reports/193799) -- Uber | $2,000 | Cross-site Scripting (XSS) - Stored | 11up
- [XSS в письме, в теле письма.](https://hackerone.com/reports/269458) -- Mail.ru | $2,000 | Cross-site Scripting (XSS) - Stored | 10up
- [Stored XSS in drive.uber.com WordPress admin panel](https://hackerone.com/reports/126099) -- Uber | $2,000 | Cross-site Scripting (XSS) - Generic | 7up
- [Reflected XSS via Livefyre Media Wall in newsroom.uber.com](https://hackerone.com/reports/134061) -- Uber | $2,000 | Cross-site Scripting (XSS) - Generic | 6up
- [Reflected XSS in OAUTH2 login flow](https://hackerone.com/reports/697099) -- LY Corporation | $1,990 | Cross-site Scripting (XSS) - Reflected | 487up
- [Stored cross-site scripting in dataset owner.](https://hackerone.com/reports/708123) -- Quantopian | $1,925 | Cross-site Scripting (XSS) - Stored | 16up
- [[Java] CWE-079: Query to detect XSS with JavaServer Faces (JSF)](https://hackerone.com/reports/1339898) -- GitHub Security Lab | $1,800 | 31up
- [XSS while logging using Google](https://hackerone.com/reports/691611) -- Shopify | $1,750 | Cross-site Scripting (XSS) - Reflected | 341up
- [CRLF and XSS stored on ton.twitter.com](https://hackerone.com/reports/191380) -- X / xAI | $1,680 | Cross-site Scripting (XSS) - Generic | 32up
- [Reflected XSS in AI Chat Bot Greetings at help.shopify.com via Markdown Image Rendering](https://hackerone.com/reports/2509022) -- Shopify | $1,600 | Cross-site Scripting (XSS) - Reflected | 107up
- [Cross-site scripting on api.collabs.shopify.com](https://hackerone.com/reports/1672459) -- Shopify | $1,600 | Cross-site Scripting (XSS) - Reflected | 51up
- [Stored XSS in Dovetale by application of creator](https://hackerone.com/reports/1652046) -- Shopify | $1,600 | Cross-site Scripting (XSS) - Stored | 34up
- [Read/Write arbitrary (non-HttpOnly) cookies on checkout pages via GoogleAnalyticsAdditionalScripts postMessage handler](https://hackerone.com/reports/1081167) -- Shopify | $1,600 | Cross-site Scripting (XSS) - Generic | 16up
- [[h1-2102] Stored XSS in product description via `productUpdate` GraphQL query leads to XSS at handshake-web-internal.shopifycloud.com/products/[ID]](https://hackerone.com/reports/1085546) -- Shopify | $1,600 | Cross-site Scripting (XSS) - Stored | 8up
- [XSS and Open Redirect on MoPub Login](https://hackerone.com/reports/683298) -- X / xAI | $1,540 | Open Redirect | 248up
- [Ability to create own account UUID leads to stored XSS](https://hackerone.com/reports/249131) -- Upserve | $1,500 | Cross-site Scripting (XSS) - Stored | 207up