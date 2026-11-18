# Open Redirect -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Reflected XSS via Unvalidated / Open Redirect in uber.com](https://hackerone.com/reports/125791) -- Uber | $3,000 | 11up
  > This report demonstrates how much the usual Open Redirect can be dangerous.  ### Open Redirect Open Redirect was reproduced from this URL: [uber.com/en//example.com/](https://www.uber.com/en//example.com/) Response:  ``` HTTP/1.1 301 ... Location: //example.com/ ```  ### CSS injection This vulnerability was reproduced via parameter `theme` from URL...
- [open redirect in rfc6749](https://hackerone.com/reports/26962) -- Internet Bug Bounty | $3,000 | Open Redirect | 7up
  > OAuth Providers (servers) that strictly follow rfc6749 are vulnerable to open redirect. Let me explain, reading [0]  If the request fails due to a missing, invalid, or mismatching    redirection URI, or if the client identifier is missing or invalid,    the authorization server SHOULD inform the resource owner of the    error and MUST NOT automatically redirect the user-agent to the   ...
- [Open Redirect Vulnerability in Action Pack](https://hackerone.com/reports/1865991) -- Internet Bug Bounty | $2,400 | Open Redirect | 43up
  > Open Redirect Vulnerability in Action Pack Description There is a vulnerability in Action Controller’s redirect_to. This vulnerability has been assigned the CVE identifier CVE-2023-22797.  Versions Affected: >= 7.0.0 Not affected: < 7.0.0 Fixed Versions: 7.0.4.1 Impact  There is a possible open redirect when using the redirect_to helper with untrusted user input.  Vulnerable code will look like...
- [XSS and Open Redirect on MoPub Login](https://hackerone.com/reports/683298) -- X / xAI | $1,540 | Open Redirect | 248up
  > Very simple open redirect made more impactful by the lack of filtering javascript URIs. Thanks again to the Twitter team for a quick response/bounty!
- [Open Redirect leak of authenticity_token lead to full account take over.](https://hackerone.com/reports/49759) -- X / xAI | $1,400 | Open Redirect | 7up
  > Hey guys URL: https://mobile.twitter.com/messages/follow?recipient=/example.com when I click 'Follow' I will send my POST request to https://example.com witch contains my authenticity_token that can be used for anything like tweeting, following, sending messages, changing username.,.,.etc it can be used too to Add a mobile number, and then steal the account by recovering it by the mobile...
- [Open redirect at https://inventory.upserve.com/http://google.com/](https://hackerone.com/reports/469803) -- Upserve | $1,200 | Open Redirect | 179up
  > The following URL is vulnerable to an open redirect (it will redirect to stanko.sh):  https://inventory.upserve.com/http://stanko.sh/  ## Impact  Users could get redirected to malicious domain.
- [[dev.twitter.com] XSS and Open Redirect](https://hackerone.com/reports/260744) -- X / xAI | $1,120 | 75up
  > http://blog.blackfan.ru/2017/09/devtwittercom-xss.html
- [[dev.twitter.com] XSS and Open Redirect Protection Bypass](https://hackerone.com/reports/330008) -- X / xAI | $1,120 | 46up
  > Description: Hi  after I finish reading the report https://hackerone.com/reports/260744.i start to test this subdomain.i fount an interesting url [https://dev.twitter.com/web/sign-inhttps://dev.twitter.com/basics/adding-international-support-to-your-apps].this url is special,my intuition tells me that this URL may have a problem.so,i try test,amzing i found a way to bypass protection.  PoC:...
- [page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise](https://hackerone.com/reports/3423013) -- LY Corporation | $1,000 | 43up
  > An open redirect vulnerability was identified in page.line.me because redirect destinations were not properly restricted to trusted domains. By abusing this behavior within an OAuth 2.0 authorization flow, an attacker could cause the authorization response to be sent to an attacker-controlled endpoint. This could expose the authorization code issued after successful user authentication, which...
- [Instant open redirect on Live preview WEB Ide opening](https://hackerone.com/reports/437142) -- GitLab | $1,000 | Open Redirect | 20up
  > Hello Gitlab team! Asset is my own gitlab installation for Ubuntu.  The issue I want to report is lack of sandbox attribute in iframe pointing to codesandbox. This results content inside iframe redirect top level window on load.  How to reproduce:  1. create index.js with following content: ``` window.open("https://evil.com","_top"); ``` 2.  create package.json with following content: ``` {  ...
- [Open Redirect (6.0.0 < rails < 6.0.3.2)](https://hackerone.com/reports/904059) -- Ruby on Rails | $1,000 | Open Redirect | 19up
  > Hello, I was looking at the change log (https://github.com/rails/rails/commit/2121b9d20b60ed503aa041ef7b926d331ed79fc2) for CVE-2020-8185 and found another problem existed.  https://github.com/rails/rails/blob/v6.0.3.1/actionpack/lib/action_dispatch/middleware/actionable_exceptions.rb#L21  ```ruby   redirect_to request.params[:location] end  private   def actionable_request?(request)    ...
- [Trick make all fixed open redirect links vulnerable again](https://hackerone.com/reports/104087) -- Slack | $1,000 | Open Redirect | 4up
  > this trick make all fixed open redirect links vulnerable again in this resolved report "https://hackerone.com/reports/2622" before fixing this link "https://slack.com/checkcookie?redir=http://www.example.com" redirect victim to "http://www.example.com"  after fixing this link "https://slack.com/checkcookie?redir=http://www.example.com" only redirect to "https://www.slack.com/" or...
- [Another window.opener issue](https://hackerone.com/reports/537840) -- Open-Xchange | $900 | Open Redirect | 33up
- [Stealing Users OAuth Tokens through redirect_uri parameter](https://hackerone.com/reports/665651) -- GSA Bounty | $750 | Open Redirect | 67up
  > I found that https://login.fr.cloud.gov/oauth/authorize has vulnerability by open redirect on oauth redirect_uri which can lead to users oauth tokens being leaked to any malicious user.  Step :  1, Clicked on link https://login.fr.cloud.gov/oauth/authorize?client_id=███&response_type=token&redirect_uri=https%3A%2F%2Fevil.com%2Fauth%2Fcallback&state=███  2, Choose any .gov account to login (...
- [Tab nabbing via window.opener](https://hackerone.com/reports/179568) -- Open-Xchange | $666 | Open Redirect | 30up

---

- [Chained open redirects and use of Ideographic Full Stop defeat Twitter's  approach to blocking links](https://hackerone.com/reports/1032610) -- X / xAI | $560 | Security Through Obscurity | 70up
- [Wrong Interpretation of URL encoded characters, showing different punny code leads to redirection on different domain](https://hackerone.com/reports/635597) -- X / xAI | $560 | Open Redirect | 37up
- [Accepting error message on twitter sends you to attacker site](https://hackerone.com/reports/781673) -- X / xAI | $560 | Open Redirect | 33up
- [open redirect sends authenticity_token to any website or (ip address)](https://hackerone.com/reports/50752) -- X / xAI | $560 | Open Redirect | 1up
- [Open Redirect in secure.showmax.com](https://hackerone.com/reports/749338) -- Showmax | $550 | Open Redirect | 225up
- [[keybase.io] Open Redirect](https://hackerone.com/reports/87027) -- Keybase | $500 | Open Redirect | 40up
- [Tab nabbing in Hackerone inbox.](https://hackerone.com/reports/1145563) -- HackerOne | $500 | Open Redirect | 23up
- [CBC "cut and paste" attack may cause Open Redirect(even XSS)](https://hackerone.com/reports/126203) -- Uber | $500 | Cryptographic Issues - Generic | 22up
- [Open redirection in OAuth](https://hackerone.com/reports/55525) -- Shopify | $500 | Open Redirect | 14up
- [[apps.shopify.com] Open Redirect](https://hackerone.com/reports/160047) -- Shopify | $500 | Open Redirect | 13up
- [Open redirect in "Language change".](https://hackerone.com/reports/52035) -- HackerOne | $500 | Open Redirect | 12up
- [Open Redirect on slack.com](https://hackerone.com/reports/140447) -- Slack | $500 | Cross-site Scripting (XSS) - Generic | 11up
- [Open Redirection on Uber.com](https://hackerone.com/reports/119236) -- Uber | $500 | Open Redirect | 11up
- [Open Redirect in riders.uber.com](https://hackerone.com/reports/125003) -- Uber | $500 | Open Redirect | 10up
- [Open Redirect in m.uber.com](https://hackerone.com/reports/125000) -- Uber | $500 | 9up
- [Redirect while opening links in new tabs](https://hackerone.com/reports/23386) -- HackerOne | $500 | Open Redirect | 8up
- [Open Redirect after login at http://ecommerce.shopify.com](https://hackerone.com/reports/55546) -- Shopify | $500 | Open Redirect | 6up
- [Redirect FILTER bypass in report/comment](https://hackerone.com/reports/28865) -- HackerOne | $500 | Open Redirect | 6up
- [OAuth access_token stealing in Phabricator](https://hackerone.com/reports/3596) -- Phabricator | $450 | Open Redirect | 9up
- [Open Redirect (verkkopalvelu.lahitapiola.fi)](https://hackerone.com/reports/179328) -- LocalTapiola | $400 | Open Redirect | 28up
- [Open Redirect bypass and cookie leakage on www.lahitapiola.com](https://hackerone.com/reports/190188) -- LocalTapiola | $400 | Open Redirect | 10up
- [OAuth Stealing Attack (New)](https://hackerone.com/reports/3930) -- Phabricator | $400 | Open Redirect | 10up
- [Reflected XSS and Open Redirect (verkkopalvelu.lahitapiola.fi)](https://hackerone.com/reports/194207) -- LocalTapiola | $400 | Cross-site Scripting (XSS) - Generic | 3up
- [Google API key leaks and security misconfiguration leads Open Redirect Vulnerability](https://hackerone.com/reports/1066410) -- Clario | $300 | Open Redirect | 68up
- [Host Header Injection leads to Open Redirect and Content Spoofing or Text Injection.](https://hackerone.com/reports/1444675) -- Omise | $300 | 50up
- [Open redirect bypass](https://hackerone.com/reports/1513031) -- Flickr | $300 | Open Redirect | 28up
- [Open Redirect и подмена ссылки в сниппете приложения VKMA](https://hackerone.com/reports/1112342) -- VK.com | $300 | Open Redirect | 28up
- [Open redirect в карусели сообщения бота](https://hackerone.com/reports/1206117) -- VK.com | $300 | Open Redirect | 18up
- [Open Redirection Vulnerability in m.vk.com](https://hackerone.com/reports/347645) -- VK.com | $300 | Open Redirect | 16up
- [Open redirect на мобильной версии в контакте (m.vk.com](https://hackerone.com/reports/456963) -- VK.com | $300 | Open Redirect | 12up
- [Open Redirect](https://hackerone.com/reports/14699) -- WePay | $300 | Open Redirect
- [Open redirection in fabric.io](https://hackerone.com/reports/39631) -- X / xAI | $280 | Open Redirect | 3up
- [Following a User Actually Follows Another User](https://hackerone.com/reports/95243) -- X / xAI | $280 | Open Redirect | 1up
- [Open Redirect](https://hackerone.com/reports/1581258) -- Flickr | $258 | Open Redirect | 15up
- [Open redirect vulnerability](https://hackerone.com/reports/380760) -- Rockstar Games | $250 | Open Redirect | 83up
- [Open Redirect](https://hackerone.com/reports/1213580) -- Affirm | $250 | Open Redirect | 74up
- [Open redirect on chaturbate.com (tipping/purchase_success)](https://hackerone.com/reports/413426) -- Chaturbate | $250 | Open Redirect | 26up
- [Event create can create attachments that link to other websites](https://hackerone.com/reports/2457588) -- Nextcloud | $250 | Open Redirect | 25up
- [Open redirect in securegatewayaccess.com / secure.chaturbate.com via prejoin_data parameter](https://hackerone.com/reports/400982) -- Chaturbate | $250 | Open Redirect | 10up
- [session takeover via open protocol redirection on streamlabs.com](https://hackerone.com/reports/1178239) -- Logitech | $200 | Open Redirect | 50up
- [Open redirect protection (https://www.pixiv.net/jump.php) is broken for novels](https://hackerone.com/reports/541862) -- pixiv | $200 | Open Redirect | 42up
- [Open Redirect at https://oauth.secure.pixiv.net](https://hackerone.com/reports/972601) -- pixiv | $200 | Open Redirect | 29up
- [Link poisoning on https://secure.login.gov/ login page](https://hackerone.com/reports/299835) -- GSA Bounty | $150 | Open Redirect | 60up
- [Redirection in Repeater & Intruder Tab](https://hackerone.com/reports/1541301) -- PortSwigger Web Security | $150 | Open Redirect | 36up
- [[idp.fr.cloud.gov] Open Redirect](https://hackerone.com/reports/387007) -- GSA Bounty | $150 | Open Redirect | 25up
- [Open redirect GET-Based on https://www.flickr.com/browser/upgrade/?continue=](https://hackerone.com/reports/1217570) -- Flickr | $150 | Open Redirect | 13up
- [open redirect in eb9f.pivcac.prod.login.gov](https://hackerone.com/reports/798742) -- GSA Bounty | $150 | Open Redirect | 13up
- [Open redirect on "Unsupported browser" warning](https://hackerone.com/reports/1977222) -- Nextcloud | $150 | Open Redirect | 8up
- [Open Redirector via (apps/files_pdfviewer) for un-authenticated users.](https://hackerone.com/reports/131082) -- ownCloud | $150 | Open Redirect | 5up
- [Unvalidated redirect on team.badoo.com](https://hackerone.com/reports/177624) -- Bumble | $140 | Cross-site Scripting (XSS) - Generic | 25up
- [Reporting user's profile by using another people's ID](https://hackerone.com/reports/47888) -- X / xAI | $140 | Open Redirect | 4up
- [Open Redirect](https://hackerone.com/reports/504751) -- Omise | $100 | Open Redirect | 72up
- [Open Redirect via Non-Latin Subdomain in vcc-*.8x8.com/AGUI/█.php](https://hackerone.com/reports/2331473) -- 8x8 | $100 | Open Redirect | 46up
- [GET based Open redirect on [streamlabs.com/content-hub/streamlabs-obs/search?query=]](https://hackerone.com/reports/978680) -- Logitech | $100 | Open Redirect | 34up
- [Hyperlink Injection in Friend Invitation Emails](https://hackerone.com/reports/164833) -- Algolia | $100 | Open Redirect | 20up
- [Hyperlink Injection in Friend Invitation Emails](https://hackerone.com/reports/158554) -- Instacart | $100 | Open Redirect | 14up
- [Open Redirect located at https://www.robinhood.com/oauth2/authorize/?](https://hackerone.com/reports/206811) -- Robinhood | $100 | Open Redirect | 11up
- [Reverse Tabnabbing in printing source document images](https://hackerone.com/reports/911123) -- Visma Public | $100 | Open Redirect | 9up
- [Open Redirect login account](https://hackerone.com/reports/16718) -- Slack | $100 | Open Redirect | 7up
- [Host Header is not validated resulting in Open Redirect](https://hackerone.com/reports/7357) -- IRCCloud | $100 | Violation of Secure Design Principles | 4up
- [Open Redirection In connect.identity.stagaws.visma.com](https://hackerone.com/reports/811356) -- Visma Public | $100 | Open Redirect | 3up
- [Hyperlink Injection on Email Invitation](https://hackerone.com/reports/843421) -- Helium | $50 | Open Redirect | 25up
- [Open Redirection leads to redirect Users to malicious website](https://hackerone.com/reports/625546) -- Unikrn | $50 | Open Redirect | 18up
- [Host Header Injection/Redirection](https://hackerone.com/reports/94637) -- Whisper | $30 | Open Redirect | 7up
- [[cs.money] Open Redirect Leads to Account Takeover](https://hackerone.com/reports/905607) -- CS Money | Improper Authentication - Generic | 356up
- [[PayPal Android] Remote theft of user session using push_notification_webview deeplink](https://hackerone.com/reports/424443) -- PayPal | Open Redirect | 188up
- [Open Redirect in Logout & Login](https://hackerone.com/reports/1788006) -- Expedia Group Bug Bounty | Open Redirect | 171up
- [[Venmo Android] Remote theft of user session](https://hackerone.com/reports/401940) -- PayPal | Open Redirect | 151up
- [Open redirect due to scanning QR code via brave browser](https://hackerone.com/reports/1946534) -- Brave Software | Open Redirect | 148up
- [Open Redirect on central.uber.com allows for account takeover](https://hackerone.com/reports/206591) -- Uber | Improper Authentication - Generic | 144up
- [Open redirect](https://hackerone.com/reports/2957962) -- XVIDEOS | Open Redirect | 143up
- [1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation](https://hackerone.com/reports/3723458) -- Khan Academy | Improper Access Control - Generic | 124up
- [Stealing xoxs-tokens using weak postMessage / call-popup redirect to current team domain](https://hackerone.com/reports/207170) -- Slack | Violation of Secure Design Principles | 120up
- [Open URL Redirection](https://hackerone.com/reports/1238684) -- Unikrn | Open Redirect | 102up
- [CRLF to XSS & Open Redirection](https://hackerone.com/reports/2012519) -- TikTok | Cross-site Scripting (XSS) - Reflected | 97up
- [Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect](https://hackerone.com/reports/499348) -- X / xAI | Improper Access Control - Generic | 95up
- [Open redirect](https://hackerone.com/reports/753399) -- Nord Security | Open Redirect | 81up
- [OAuth redirect uri validation bypass for :proxima_first_party_sync apps](https://hackerone.com/reports/3588801) -- GitHub | Open Redirect | 78up
- [another liberapay member team twitter account broken Link Hijacking via Expired Twitter Account Link](https://hackerone.com/reports/3723002) -- Liberapay | Open Redirect | 77up
- [Open Redirect on ███████](https://hackerone.com/reports/2265413) -- Fastly VDP | Open Redirect | 74up
- [Bypass of Open Redirect Fix on lovable.dev via /..// Path Traversal in redirect parameter](https://hackerone.com/reports/3599248) -- Lovable VDP | Open Redirect | 73up
- [open redirected by host header](https://hackerone.com/reports/2828499) -- Localize | Open Redirect | 73up
- [Identity Login Page Redirect Can Be Manipulated](https://hackerone.com/reports/243474) -- Inflection | Open Redirect | 72up
- [Possible to redirect to a (non-existing) subdomain after logging in via GitHub (leaking the token)](https://hackerone.com/reports/292825) -- Ed | Open Redirect | 71up
- [Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack](https://hackerone.com/reports/3099816) -- Lichess | Open Redirect | 70up