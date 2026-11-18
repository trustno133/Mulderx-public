# Auth Bypass -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Incorrect authorization to the intelbot service leading to ticket information](https://hackerone.com/reports/1328546) -- TikTok | $15,000 | Improper Authentication - Generic | 218up
  > An authentication bypass and site wide stored XSS (cross-site scripting) vulnerability was found on TikTok Ads as JWT (JSON Web Token) was not verified properly. We thank @johnstone for reporting this to our team and confirming its resolution.
- [Account Takeover via Authentication Bypass in TikTok Account Recovery](https://hackerone.com/reports/2443228) -- TikTok | $12,000 | Authentication Bypass Using an Alternate Path or Channel | 172up
  > An improper authentication mechanism in TikTok's account recovery process could have been used for account takeovers on Android devices. There was no evidence of exploitation and this vulnerability has now been completely fixed. We thank @xtt0k for reporting this to our team and confirming its remediation.
- [Ability to DOS any organization's SSO and open up the door to account takeovers](https://hackerone.com/reports/976603) -- Superhuman (formerly Grammarly) | $10,500 | Improper Authentication - Generic | 259up
  > The vulnerability was fixed before SSO became available to Grammarly customers.
- [Authentication bypass on gist.github.com through SSH Certificates](https://hackerone.com/reports/1901040) -- GitHub | $10,000 | Improper Access Control - Generic | 182up
  > An improper authentication vulnerability was identified in GitHub Enterprise Server that allowed an unauthorized actor to modify other users' secret gists by authenticating through an SSH certificate authority. To do so, a user had to know the secret gist's URL. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.9 and was fixed in versions 3.4.18, 3.5.15, 3.6.11,...
- [password reset token leaking allowed for ATO of an Uber account](https://hackerone.com/reports/173551) -- Uber | $10,000 | Improper Authentication - Generic | 100up
  > With an email address for a valid Uber account, it was possible to take over that account because the reset token was exposed in the response of a password reset HTTP request. This meant an attacker could initiate password reset for an account and immediately receive the reset token for that account.  We consider the security of our user's data top priority, so we were very interested in this...
- [OneLogin authentication bypass on WordPress sites](https://hackerone.com/reports/136169) -- Uber | $10,000 | Improper Authentication - Generic | 58up
  > First, I'm sorry about reporting another WordPress bug (my intention was just to check if WP-OneLogin stores any sensitive info that could be used to attack OneLogin on your other websites).  #Overview# The *.uber.com WordPress sites use OneLogin SAML-SSO instead of the normal WordPress login. The WordPress plugin shipped by OneLogin has a bug which allows anyone to login without a password or...
- [Exposure of a valid Gitlab-Workhorse JWT leading to various bad things](https://hackerone.com/reports/1040786) -- GitLab | $10,000 | Improper Authentication - Generic | 36up
  > ### Summary  Using the **State** Uploading API we could potentially do a bad thing: - Bypass `Gitlab::Workhorse.verify_api_request!`  This was due to the fact that Workhorse clean the URL before passing it to Rails, this is elaborated in #923027.  and **State** Api read `request.body` to append it as a file!  **lib/api/terraform/state.rb** ```ruby  desc 'Add a new terraform state or update an...
- [SAML Authentication Bypass on uchat.uberinternal.com](https://hackerone.com/reports/223014) -- Uber | $8,500 | Improper Authentication - Generic | 87up
  > Due to improper SAML verification it was possible to bypass the OneLogin authentication on https://uchat.uberinternal.com and gain unauthorized access to internal chats.  We enjoyed working with @mishre on this report and look forward to receiving more submissions from them in the future!
- [[CRITICAL] -- Complete Account Takeover](https://hackerone.com/reports/136885) -- Uber | $8,000 | Improper Authentication - Generic | 88up
  > Thanks for another great find @parth!
- [Stealing SSO Login Tokens (snappublisher.snapchat.com)](https://hackerone.com/reports/265943) -- Snapchat | $7,500 | Authentication Bypass | 244up
  > @coolboss was able to chain multiple security issues, which allowed him to extract SSO tokens from Snapchat users by sending them to a malicious website.
- [OneLogin authentication bypass on WordPress sites via XMLRPC](https://hackerone.com/reports/138869) -- Uber | $7,000 | Code Injection | 83up
  > When a user logs on one of your WordPress sites via OneLogin, the authentication plugin creates a new entry in the WordPress user database with the default password `@@@nopass@@@`. This wouldn't be a problem if the plugin disabled all normal WordPress authentication methods, but it doesn't.  The OneLogin plugin does prevent logins through the normal *wp-login.php* page but fails to restrict the...
- [Access to some Slack workspace metadata and settings available to unauthorized parties](https://hackerone.com/reports/130133) -- Slack | $7,000 | Improper Authentication - Generic | 60up
  > In April 2016, @secalert alerted us to a vulnerability which may have allowed access to some Slack workspace metadata and settings to unauthorized parties. We implemented an initial fix within minutes, and a complete fix within two weeks. Nothing further is required from users to be protected.   Thank you to @secalert for finding this!
- [Able to steal bearer token from deep link](https://hackerone.com/reports/1372667) -- Basecamp | $6,337 | Improper Authentication - Generic | 109up
  > # Pre-requisities  Prior to exploitation you would be required to know the "account id" of the user that you are attacking. Whilst this makes it difficult to attack an application in a generic way - the account is not secret information as it is included in any links to a user's basecamp organisation. E.g  https://3.basecamp.com/5218370/  # Attack  The attack involves forcing the user to enter...
- [Mint Oauth2 access token for targeted user](https://hackerone.com/reports/1148364) -- GitLab | $5,580 | Improper Authentication - Generic | 138up
  > ### Summary  It is possible to mint access token for targeted user. There is a flaw for group level application setup. It allows a group owner to create an application with user's trust by default. This bypassed the CSRF control for authorization flow.   ### Steps to reproduce   1. Login as user1 , create a group called malicious group  2. Create an Applications in Settings > Applications > api...
- [Weak user aunthentication on mobile application - I just broken userKey secret password](https://hackerone.com/reports/138101) -- Pornhub | $5,000 | Improper Authentication - Generic | 29up

---

- [[JAVA]: CWE-347 - Improper Verification of Cryptographic Signature : Potential for Auth Bypass](https://hackerone.com/reports/1184041) -- GitHub Security Lab | $4,500 | 2up
- [Attacker can obtain write access to any federated share/public link](https://hackerone.com/reports/1170024) -- Nextcloud | $4,000 | Improper Authentication - Generic | 142up
- [Admin Panel Accessed (OAuth Bypassed )](https://hackerone.com/reports/294911) -- Mapbox | $4,000 | Command Injection - Generic | 133up
- [[JAVA]: CWE-347 - Improper Verification of Cryptographic Signature : Potential for Auth Bypass](https://hackerone.com/reports/1212274) -- GitHub Security Lab | $4,000 | 4up
- [Unsecured Elasticsearch Instance](https://hackerone.com/reports/267161) -- Pornhub | $3,500 | Improper Authentication - Generic | 36up
- [Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties](https://hackerone.com/reports/922456) -- GitLab | $3,000 | Authentication Bypass Using an Alternate Path or Channel | 257up
- [HackerOne Jira integration plugin Leaked JWT to unauthorized jira users](https://hackerone.com/reports/1103582) -- HackerOne | $3,000 | Improper Authentication - Generic | 213up
- [H1514 [*.(my)shopify.com] - Viewing Password Protected Content](https://hackerone.com/reports/421859) -- Shopify | $3,000 | Improper Authentication - Generic | 192up
- [Leak ██████████ information in real time through API request](https://hackerone.com/reports/307050) -- Grab | $3,000 | Improper Authentication - Generic | 103up
- [Уязвимость в приложении для Android](https://hackerone.com/reports/1343528) -- VK.com | $3,000 | Improper Authentication - Generic | 52up
- [Missing authentication in buddy group API of LINE TIMELINE](https://hackerone.com/reports/1283938) -- LY Corporation | $3,000 | Improper Authentication - Generic | 47up
- [Get organization info base on uuid](https://hackerone.com/reports/151465) -- Uber | $3,000 | Improper Authentication - Generic | 26up
- [“email” MFA mode allows bypassing MFA from victim’s device when the device trust is not expired](https://hackerone.com/reports/665722) -- Superhuman (formerly Grammarly) | $2,500 | Improper Authentication - Generic | 82up
- [Bypass validation parts in AWS IAM Authenticator for Kubernetes](https://hackerone.com/reports/1580493) -- Kubernetes | $2,500 | Improper Authentication - Generic | 68up
- [Authentication Bypass in ID4me handling via Missing JWT Signature Verification in User OIDC](https://hackerone.com/reports/3489490) -- Nextcloud | $2,500 | Improper Authentication - Generic | 55up
- [Unprotected Memcache Installation running](https://hackerone.com/reports/119871) -- Pornhub | $2,500 | Improper Authentication - Generic | 9up
- [Unauthorized access to all collections, products, pages from other stores](https://hackerone.com/reports/93921) -- Shopify | $2,500 | Improper Authentication - Generic | 6up
- [unauthorized access to all customers first and last name](https://hackerone.com/reports/92453) -- Shopify | $2,500 | Improper Authentication - Generic | 4up
- [TLS client authentication can be bypassed due to ticket resumption](https://hackerone.com/reports/2978267) -- Internet Bug Bounty | $2,162 | Improper Authentication - Generic | 31up
- [Account Takeover via Email ID Change and Forgot Password Functionality](https://hackerone.com/reports/1089467) -- New Relic | $2,048 | Improper Authentication - Generic | 214up
- [Improper Validation at Partners Login](https://hackerone.com/reports/990048) -- Eternal | $2,000 | Improper Authentication - Generic | 251up
- [Improper bot-authentication allows to impersonate any user when sending messages in a room](https://hackerone.com/reports/3329310) -- Basecamp | $2,000 | Improper Authentication - Generic | 128up
- [User able to access company details in yrityspalvelu without proper permissions](https://hackerone.com/reports/213418) -- LocalTapiola | $2,000 | Improper Authentication - Generic | 63up
- [Authentication Bypass with usage of PreSignedURL](https://hackerone.com/reports/2337427) -- ownCloud | $2,000 | Improper Access Control - Generic | 44up
- [Taskcluster web-server OAuth2 authorization codes are reusable and the exchange handler checks the wrong expiry column](https://hackerone.com/reports/3734676) -- Mozilla | $2,000 | Authentication Bypass by Capture-replay | 41up
- [Traffic amplification attack via discovery protocol](https://hackerone.com/reports/502207) -- Rootstock Labs | $2,000 | Improper Authentication - Generic | 25up
- [Authentication bypass leads to sensitive data exposure (token+secret)](https://hackerone.com/reports/129918) -- Slack | $2,000 | Improper Authentication - Generic | 10up
- [[IODR] Get business trip via organization id](https://hackerone.com/reports/151470) -- Uber | $2,000 | Improper Authentication - Generic | 10up
- [Arbitrary write on s3://shopify-delivery-app-storage/files](https://hackerone.com/reports/93691) -- Shopify | $2,000 | Improper Authentication - Generic | 5up
- [Ability to connect an external login service for unverified emails/accounts at accounts.shopify.com](https://hackerone.com/reports/1018489) -- Shopify | $1,600 | Improper Authentication - Generic | 29up
- [TikTok 2FA Bypass](https://hackerone.com/reports/1247108) -- TikTok | $1,564 | Improper Authorization | 194up
- [Critical full compromise of jarvis-new.urbanclap.com via weak session signing](https://hackerone.com/reports/1380121) -- Urban Company | $1,500 | Improper Authentication - Generic | 123up
- [Unauthorized access to GovSlack](https://hackerone.com/reports/1758174) -- Slack | $1,500 | Improper Authentication - Generic | 81up
- [[idor] Unauthorized Read access to all the private posts(Including Photos,Videos,Gifs)](https://hackerone.com/reports/148764) -- Pornhub | $1,500 | Improper Authentication - Generic | 58up
- [IDOR - disclosure of private videos - /api_android_v3/getUserVideos](https://hackerone.com/reports/186279) -- Pornhub | $1,500 | Improper Authentication - Generic | 32up
- [SDC bypass on calendar.mail.ru](https://hackerone.com/reports/1024029) -- Mail.ru | $1,500 | Authentication Bypass Using an Alternate Path or Channel | 31up
- [SDC bypass cloud.mail.ru for every /api/v3/* endpoint.](https://hackerone.com/reports/1033895) -- Mail.ru | $1,500 | Authentication Bypass Using an Alternate Path or Channel | 20up
- [External programs revealing info](https://hackerone.com/reports/124929) -- HackerOne | $1,500 | Improper Authentication - Generic | 8up
- [Arbitrary read on s3://shopify-delivery-app-storage/files](https://hackerone.com/reports/94087) -- Shopify | $1,500 | Improper Authentication - Generic | 3up
- [Problem with OAuth](https://hackerone.com/reports/46485) -- X / xAI | $1,260 | Improper Authentication - Generic | 7up
- [Changing details of other users profile using UUID (IDOR)](https://hackerone.com/reports/195996) -- Showmax | $1,200 | Improper Authentication - Generic | 36up
- [Второй способ обхода 2FA](https://hackerone.com/reports/167121) -- VK.com | $1,050 | Improper Authentication - Generic | 17up
- [OTP token bypass in accessing user settings](https://hackerone.com/reports/699082) -- Razer | $1,000 | Improper Authentication - Generic | 339up
- [Login to any account with the emailaddress](https://hackerone.com/reports/245408) -- Eternal | $1,000 | Improper Authentication - Generic | 103up
- [Eavesdropping on private Slack calls](https://hackerone.com/reports/184698) -- Slack | $1,000 | Improper Authentication - Generic | 68up
- [Administrator access to a Django Administration Panel on *.sc-corp.net via bruteforced credentials](https://hackerone.com/reports/128114) -- Snapchat | $1,000 | Improper Authentication - Generic | 54up
- [Account deletion using the /v1/account/destroy API endpoint using account password without 2FA verification](https://hackerone.com/reports/2197244) -- Mozilla | $1,000 | Improper Authentication - Generic | 52up
- [S3 bucket takeover due to proxy.harvestfiles.com](https://hackerone.com/reports/152584) -- Harvest | $1,000 | Improper Authentication - Generic | 38up
- [Sign in with Apple works on existing accounts, bypasses 2FA](https://hackerone.com/reports/1593404) -- Cloudflare Public Bug Bounty | $1,000 | Improper Authentication - Generic | 32up
- [Ability to by-pass second factor](https://hackerone.com/reports/2419776) -- Nextcloud | $1,000 | Improper Authentication - Generic | 29up
- [IDOR expire other user sessions](https://hackerone.com/reports/56511) -- Shopify | $1,000 | Improper Authentication - Generic | 29up
- [Username restriction bypass with SSL client authentication](https://hackerone.com/reports/480928) -- Open-Xchange | $1,000 | Improper Authentication - Generic | 26up
- [Account Takeover on https://www.delivery-club.ru через партнерский аккаунт.](https://hackerone.com/reports/324230) -- Mail.ru | $1,000 | Improper Authentication - Generic | 22up
- [Обход 2ух-шаговой авторизации / 2FA Bypass](https://hackerone.com/reports/163834) -- VK.com | $1,000 | Improper Authentication - Generic | 21up
- [Unauthorized access to Zookeeper on http://locutus-zk3.ec2.shopify.com:2181](https://hackerone.com/reports/154369) -- Shopify | $1,000 | Improper Authentication - Generic | 20up
- [Bypassing 2FA for BTC transfers](https://hackerone.com/reports/10554) -- Coinbase | $1,000 | Improper Authentication - Generic | 18up
- [Account takeover via Pornhub Oauth](https://hackerone.com/reports/192648) -- Pornhub | $1,000 | Improper Authentication - Generic | 17up
- [Bypass auth.email-domains](https://hackerone.com/reports/2224) -- Phabricator | $1,000 | Improper Authentication - Generic | 15up
- [S3 Buckets open to the world thanks to  'Authenticated Users' ACL](https://hackerone.com/reports/98819) -- Shopify | $1,000 | Improper Authentication - Generic | 14up
- [Account hijack via deleted PH account](https://hackerone.com/reports/201940) -- Pornhub | $1,000 | Improper Authentication - Generic | 13up
- [Новый 2FA Bypass](https://hackerone.com/reports/179421) -- VK.com | $1,000 | Improper Authentication - Generic | 12up
- [API Key added for one Indices works for all other indices too.](https://hackerone.com/reports/118925) -- Algolia | $1,000 | Improper Authentication - Generic | 6up
- [create staff member without owner access](https://hackerone.com/reports/90688) -- Shopify | $1,000 | Improper Authentication - Generic | 5up
- [Wordpress Vulnerabilities in transparencyreport.uber.com and eng.uber.com domains](https://hackerone.com/reports/148163) -- Uber | $1,000 | Improper Authentication - Generic | 4up
- [change Login Services settings without owner access](https://hackerone.com/reports/90690) -- Shopify | $1,000 | Improper Authentication - Generic | 4up
- [Bypass access restrictions from API](https://hackerone.com/reports/67557) -- Shopify | $1,000 | Improper Authentication - Generic | 4up
- [Sending payments via QR code does not require confirmation](https://hackerone.com/reports/126784) -- Coinbase | $1,000 | Improper Authentication - Generic | 3up
- [Unauthenticated access to details of hidden products in any shop via title emuneration](https://hackerone.com/reports/93394) -- Shopify | $1,000 | Improper Authentication - Generic | 3up
- [Improper Authentication inside the Rockstar Games Launcher which leads to Account takeover to some extend](https://hackerone.com/reports/1442783) -- Rockstar Games | $750 | Improper Authentication - Generic | 51up
- [bypass of 2FA](https://hackerone.com/reports/248656) -- Nextcloud | $750 | Improper Authentication - Generic | 20up
- [resetreportedcount & updatetags doesn't verify appid param](https://hackerone.com/reports/351106) -- Valve | $750 | Improper Authentication - Generic | 19up
- [Unsecured Grafana instance](https://hackerone.com/reports/167585) -- Pornhub | $750 | Improper Authentication - Generic | 18up
- [Disclosure of private photos/albums - http://www.pornhub.com/album/show_image_box](https://hackerone.com/reports/167582) -- Pornhub | $750 | Improper Authentication - Generic | 9up
- [[idor] Profile Admin can pin any other user's post on his stream wall](https://hackerone.com/reports/138852) -- Pornhub | $750 | Improper Authentication - Generic | 7up
- [Воскрешение сессии после сброса сессий / смены пароля / принудительной смены пароля](https://hackerone.com/reports/207062) -- VK.com | $700 | Improper Authentication - Generic | 7up
- [Twitter Ads Campaign information disclosure through admin without any authentication.](https://hackerone.com/reports/49806) -- X / xAI | $560 | Improper Authentication - Generic | 6up
- [[CRITICAL]-Taking over entire subdomain of romit.io](https://hackerone.com/reports/173681) -- Enter | $513 | Improper Authentication - Generic | 35up
- [Broken OAuth leads to change photo profile users .](https://hackerone.com/reports/642475) -- Dropbox | $512 | Improper Authentication - Generic | 37up
- [Bypass of biometrics security functionality is possible in Android application (com.shopify.mobile)](https://hackerone.com/reports/637194) -- Shopify | $500 | Improper Authentication - Generic | 90up
- [Unauthenticated GraphQL access by prepending __schema to private operations](https://hackerone.com/reports/3452015) -- Enjin | $500 | Authentication Bypass | 75up
- [Subdomain Takeover Via unclaimed Heroku Instance tim-exclusive.shopify.com](https://hackerone.com/reports/424669) -- Shopify | $500 | Improper Authentication - Generic | 68up
- [many commands can be manipulated to delete identities or affiliations](https://hackerone.com/reports/348090) -- Linux Foundation Decentralized Trust | $500 | Improper Authentication - Generic | 43up
- [Open Aws Amazon S3 Buckets](https://hackerone.com/reports/222724) -- Mapbox | $500 | Improper Authentication - Generic | 39up
- [Full Account Takeover In ****.ru](https://hackerone.com/reports/1078479) -- Mail.ru | $500 | Authentication Bypass Using an Alternate Path or Channel | 35up
- [Rate-limit bypass](https://hackerone.com/reports/165727) -- Slack | $500 | Improper Authentication - Generic | 27up