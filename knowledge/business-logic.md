# Business Logic -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Ability to bypass partner email confirmation to take over any store given an employee email](https://hackerone.com/reports/300305) -- Shopify | $15,250 | Time-of-check Time-of-use (TOCTOU) Race Condition | 272up
  > @cache-money reported it was possible to bypass the email verification process in our Partners Dashboard. Doing so would have allowed a Partner to request access to a store under an email address the Partner did not own. If the store had a staff account associated with that email address, the staff account would have been automatically converted to a "collaborator" account and added to the...
- [An attacker can run pipeline jobs as arbitrary user](https://hackerone.com/reports/894569) -- GitLab | $12,000 | Business Logic Errors | 307up
  > ### Summary  An attacker can run arbitrary pipeline jobs as a `victim` user. This means the attacker can access the user private repositories, member only repositories, registry, etc... by using the victim `CI_JOB_TOKEN` token.  > This is only my recent research and I wanted to report it as soon as possible. I will update the report with more information later on.  ### Steps to...
- [Double Payout via PayPal](https://hackerone.com/reports/307239) -- Coinbase | $10,000 | Business Logic Errors | 322up
  > An issue with the handling of the PayPal transaction states resulted in a user being able to both withdraw money from PayPal, but not have the funds deducted from their account.
- [Using gossip to drain miner wallets](https://hackerone.com/reports/1058879) -- Zilliqa | $10,000 | Improper Authorization | 111up
- [Modify in-flight data to payment provider Smart2Pay](https://hackerone.com/reports/1295844) -- Valve | $7,500 | Business Logic Errors | 442up
  > I have found vulnerability which allows attacker to generate steam wallet balance.  Firstly you will have to change yours steam account email to something like (I will explain why in next steps, amount100 is the important part):  brixamount100abc@█████  Then go to https://store.steampowered.com/steamaccount/addfunds and click add add funds.  Proceed to payment and select any payment which uses...
- [Fee discounts can be redeemed many times, resulting in unlimited fee-free transactions](https://hackerone.com/reports/1849626) -- Stripe | $5,000 | Business Logic Errors | 266up
  > ## Summary: Hi there, first off, I am an actual Stripe customer using Stripe for my real business, so I used my actual Stripe account to test this (as there is no other way). I realize this is not ideal but hope you understand given the unique scenario!  I was recently offered a fee discount of $20,000 on Stripe transactions. Stripe Support applied the offer to my account, and I was shown a...
- [Able to approve admin approval and change effective status without adding payment details .](https://hackerone.com/reports/1543159) -- Reddit | $5,000 | Business Logic Errors | 191up
  > ## Summary:  In https://ads.reddit.com/ you can create campaign under which you can create ads , once you create new campaign , it is on pending stage and will not be delivered unless you add payment details and is reviewed by admin and approved according to what it says here https://advertising.reddithelp.com/en/categories/ad-review/about-reddits-ad-review-process . But changing the value of...
- [Дюп предметов lootdog и возможность их продавать.](https://hackerone.com/reports/470041) -- Mail.ru | $5,000 | Business Logic Errors | 73up
- [Race condition in faucet when using starport](https://hackerone.com/reports/1438052) -- Cosmos | $5,000 | 60up
  > The proper writeup of the bug can be found here at our blogpost https://blog.credshields.com/race-condition-in-tendermints-starport-7cebe176d935  The root cause of the bug was in function “Transfer” at https://github.com/tendermint/starport/blob/7812125/starport/pkg/cosmosfaucet/transfer.go#L50-L74 We can notice in the code that each request to the faucet causes two actions to be made; one for...
- [A miner can manipulate the gas reporting bond](https://hackerone.com/reports/377398) -- Augur | $5,000 | Business Logic Errors | 34up
- [Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust standard library](https://hackerone.com/reports/1520931) -- Internet Bug Bounty | $4,000 | Time-of-check Time-of-use (TOCTOU) Race Condition | 9up
  > Race condition in std::fs::remove_dir_all Description This is a cross-post of the official security advisory. The official advisory contains a signed version with our PGP key, as well.  The Rust Security Response WG was notified that the std::fs::remove_dir_all standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker could use this security...
- [Non-premium user can disable Ads in japanese version of dic.pixiv.net](https://hackerone.com/reports/3183520) -- pixiv | $3,000 | Business Logic Errors | 121up
  > ## Summary  A vulnerability is identified in the Japanese version of the pixiv dictionary website (`dic.pixiv.net`) where non-premium users can disable advertisements. Normally, the ability to disable ads is restricted to premium users only, as indicated by the "P" icon next to the ad display settings in the user profile. However, due to improper access control at the API endpoint...
- [XSS on any Shopify shop via abuse of the HTML5 structured clone algorithm in postMessage listener on "/:id/digital_wallets/dialog"](https://hackerone.com/reports/231053) -- Shopify | $3,000 | Cross-site Scripting (XSS) - DOM | 121up
  > This issue is a XSS affecting all Shopify stores that can be triggered via `windows.postMessage` from any remote origin. The report demonstrated a clever bypass of the escaping code we had in place to prevent code injection.
- [Race Condition Enables Bypassing Verification Check](https://hackerone.com/reports/2110030) -- Tools for Humanity | $3,000 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | 95up
  > A race condition was discovered in the WorldID platform that could enable bypassing the verification check limits under certain conditions. The issue resided in the enforcement of maximum allowed verifications, which was not properly synchronized across parallel requests to the cloud backend service.  The fix implemented enforcement of the maximum verifications in the database, making it the...
- [[help.steampowered.com] Account takeover bruteforcing SteamGuard](https://hackerone.com/reports/407971) -- Valve | $2,500 | Business Logic Errors | 112up
  > Due to a missing protection on a support endpoint, email verification codes could be bruteforced - leading to possible account takeover. The endpoint issue has been corrected.

---

- [Harvesting all private invites using leave program fast-tracked invitation and security@ email forwarding feature](https://hackerone.com/reports/334205) -- HackerOne | $2,500 | Business Logic Errors | 103up
- [[curl] CVE-2023-32001: fopen race condition](https://hackerone.com/reports/2078571) -- Internet Bug Bounty | $2,480 | Time-of-check Time-of-use (TOCTOU) Race Condition | 21up
- [CVE-2023-27535: FTP too eager connection reuse](https://hackerone.com/reports/1912778) -- Internet Bug Bounty | $2,400 | Business Logic Errors | 21up
- [CVE-2022-27778: curl removes wrong file on error](https://hackerone.com/reports/1565623) -- Internet Bug Bounty | $2,400 | Business Logic Errors | 11up
- [CVE-2022-27782: TLS and SSH connection too eager reuse](https://hackerone.com/reports/1565624) -- Internet Bug Bounty | $2,400 | Business Logic Errors | 11up
- [CVE-2022-32207: Unpreserved file permissions](https://hackerone.com/reports/1614331) -- Internet Bug Bounty | $2,400 | Business Logic Errors | 7up
- [Change phone number OTP flaw leads to any phone number takeover](https://hackerone.com/reports/2588329) -- inDrive | $2,000 | Business Logic Errors | 241up
- [Race condition in activating email resulting in infinite amount of diamonds received](https://hackerone.com/reports/509629) -- InnoGames | $2,000 | Time-of-check Time-of-use (TOCTOU) Race Condition | 137up
- [Add upto 10K rupees to a wallet by paying an arbitrary amount](https://hackerone.com/reports/1408782) -- Eternal | $2,000 | Business Logic Errors | 132up
- [Availing Zomato gold by using a random third-party `wallet_id`](https://hackerone.com/reports/938021) -- Eternal | $2,000 | Business Logic Errors | 116up
- [Keybase extension hostname-validation regular expression issue.](https://hackerone.com/reports/307672) -- Keybase | $2,000 | Business Logic Errors | 37up
- [Indisputable Reporting via Arbitrarily Large Initial Reports](https://hackerone.com/reports/397194) -- Augur | $2,000 | Business Logic Errors | 20up
- [Adobe Flash Player Race Condition Vulnerability](https://hackerone.com/reports/119657) -- Internet Bug Bounty | $2,000 | Memory Corruption - Generic | 5up
- [worki.ru: SMS code bruteforce](https://hackerone.com/reports/700612) -- Mail.ru | $1,657 | Business Logic Errors | 136up
- [Change the rating of any trip, therefore change the average driver rating](https://hackerone.com/reports/724522) -- Uber | $1,500 | Business Logic Errors | 43up
- [Opportunity to obtain private tweets through search widget preview caches](https://hackerone.com/reports/263760) -- X / xAI | $1,120 | Business Logic Errors | 48up
- [Exploitable live argument in onClick Function leads to Data Leakage of Inactive/Suspended Products](https://hackerone.com/reports/2295958) -- TikTok | $1,000 | Business Logic Errors | 128up
- [Improper use of "path" parameter can be used to trick testers into leaking their Front-End PoC](https://hackerone.com/reports/926221) -- BugPoC | $1,000 | Business Logic Errors | 71up
- [Claiming ownership of GitHub handles via forked GitHub gists.](https://hackerone.com/reports/307675) -- Keybase | $1,000 | Business Logic Errors | 71up
- [Changing Victim's JIRA Integration Settings Through Multiple Bugs](https://hackerone.com/reports/226199) -- HackerOne | $1,000 | Business Logic Errors | 36up
- [Race condition на market.games.mail.ru](https://hackerone.com/reports/317557) -- Mail.ru | $1,000 | Write-what-where Condition | 31up
- [Claiming package names in GitLab's automatic package referencer.](https://hackerone.com/reports/462503) -- GitLab | $1,000 | Business Logic Errors | 26up
- [Using GitLab to monitor and hijack domains in mass quantity.](https://hackerone.com/reports/312118) -- GitLab | $750 | Business Logic Errors | 39up
- [Shared-channel BETA persists integration after unshare](https://hackerone.com/reports/291822) -- Slack | $750 | Business Logic Errors | 13up
- [[Synthetics/Infrastructure/everything] Individual account permissions are not properly managed and inherited on sub accounts](https://hackerone.com/reports/268541) -- New Relic | $750 | Business Logic Errors | 6up
- [Manipulation of submit payment request allows me to obtain Infrastructure Pro/Other Services for free or at greatly reduced price](https://hackerone.com/reports/219356) -- New Relic | $600 | Business Logic Errors | 4up
- [Delete direct message history without access the proper conversation_id](https://hackerone.com/reports/666632) -- X / xAI | $560 | Business Logic Errors | 33up
- [Race Condition Vulnerability On Pornhubpremium.com](https://hackerone.com/reports/183624) -- Pornhub | $520 | 13up
- [adding h1_analyst_* to username for normal users](https://hackerone.com/reports/1770797) -- HackerOne | $500 | Business Logic Errors | 186up
- [critical server misconfiguration lead to access to any user sensitive data which include user email and password](https://hackerone.com/reports/1365738) -- Flickr | $500 | Business Logic Errors | 116up
- [Race condition in joining CTF group](https://hackerone.com/reports/1540969) -- HackerOne | $500 | Time-of-check Time-of-use (TOCTOU) Race Condition | 72up
- [File sizes may be manipulated into negative numbers when uploading](https://hackerone.com/reports/1068301) -- LY Corporation | $500 | Business Logic Errors | 59up
- [Subdomain takeover of www█████████.affirm.com](https://hackerone.com/reports/1297689) -- Affirm | $500 | Business Logic Errors | 55up
- [Email Forwarding invitations for Drafts are not marked as accepted, allowing multiple users to join a program after disabling Email Forwarding](https://hackerone.com/reports/331691) -- HackerOne | $500 | Business Logic Errors | 54up
- [Response program can display "eligible for bounty" in scope area in program policy](https://hackerone.com/reports/475660) -- HackerOne | $500 | Business Logic Errors | 47up
- [Response program can create bounty table](https://hackerone.com/reports/460920) -- HackerOne | $500 | Business Logic Errors | 46up
- [IDOR to pay less for coin purchases on oauth.reddit.com via /api/v2/gold/paypal/create_coin_purchase_order in `order_id` parameter](https://hackerone.com/reports/1213765) -- Reddit | $500 | Business Logic Errors | 42up
- [Race condition at create new Location](https://hackerone.com/reports/413759) -- Shopify | $500 | Business Logic Errors | 36up
- [Dangling cloud instance at vpn.inverselink.com](https://hackerone.com/reports/1112679) -- HackerOne | $500 | Business Logic Errors | 29up
- [Submitting report through Embedded Submission form gives user indefinite access to a profile](https://hackerone.com/reports/463828) -- HackerOne | $500 | Business Logic Errors | 29up
- [User can link non-public file attachments, leading to file disclose on edit by higher-privileged user](https://hackerone.com/reports/763177) -- Phabricator | $500 | Business Logic Errors | 20up
- [Insufficient validation of sides/modifiers quantity](https://hackerone.com/reports/361960) -- Upserve | $500 | Business Logic Errors | 10up
- [Logic flaw enables restricted account to access account license key](https://hackerone.com/reports/200576) -- New Relic | $500 | Privilege Escalation | 8up
- [CVE-2023-27538: SSH connection too eager reuse still](https://hackerone.com/reports/1912783) -- Internet Bug Bounty | $480 | Business Logic Errors | 12up
- [CVE-2023-27536: GSS delegation too eager connection re-use](https://hackerone.com/reports/1912782) -- Internet Bug Bounty | $480 | Business Logic Errors | 12up
- [CVE-2023-27533: TELNET option IAC injection](https://hackerone.com/reports/1912770) -- Internet Bug Bounty | $480 | Business Logic Errors | 11up
- [CVE-2022-32208: FTP-KRB bad message verification](https://hackerone.com/reports/1614332) -- Internet Bug Bounty | $480 | Business Logic Errors | 11up
- [CVE-2023-27534: SFTP path ~ resolving discrepancy](https://hackerone.com/reports/1912777) -- Internet Bug Bounty | $480 | Business Logic Errors | 10up
- [CVE-2023-23914: HSTS ignored on multiple requests](https://hackerone.com/reports/1874715) -- Internet Bug Bounty | $480 | Business Logic Errors | 8up
- [CVE-2023-23915: HSTS amnesia with --parallel](https://hackerone.com/reports/1874716) -- Internet Bug Bounty | $480 | Business Logic Errors | 8up
- [CVE-2023-28320 - siglongjmp race condition](https://hackerone.com/reports/1990421) -- Internet Bug Bounty | $480 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | 7up
- [Critical broken cookie signing on dagobah.flickr.com](https://hackerone.com/reports/1440290) -- Flickr | $479 | Business Logic Errors | 30up
- [Client can redirect payment, causing payment discrepancy between Harvest and PayPal](https://hackerone.com/reports/219215) -- Harvest | $400 | Business Logic Errors | 34up
- [Subdomain takeover of fr1.vpn.zomans.com](https://hackerone.com/reports/1182864) -- Eternal | $350 | Business Logic Errors | 99up
- [Authorization Bypass in Starknet Snap via enableAuthorize parameter leads to unauthorized transaction signing](https://hackerone.com/reports/3507241) -- MetaMask | $350 | Business Logic Errors | 85up
- [Abusing "Report as abuse" functionality to delete any user's post.](https://hackerone.com/reports/411075) -- Vanilla | $300 | Business Logic Errors | 160up
- [Unlock underage blocked app without support interaction using airplane mode](https://hackerone.com/reports/3136790) -- Tools for Humanity | $300 | Business Logic Errors | 65up
- [Unsanitized user photo paths allow local file read](https://hackerone.com/reports/484615) -- Vanilla | $300 | Business Logic Errors | 31up
- [No rate Limit on Licenses Activation](https://hackerone.com/reports/911880) -- Clario | $300 | Business Logic Errors | 28up
- [Общий CSRF токен для сообщений сообществ, или как подставить соседа-редактора](https://hackerone.com/reports/315524) -- VK.com | $300 | Business Logic Errors | 20up
- [Race Condition of Transfer data Credits to Organization Leads to Add Extra free Data Credits to the Organization](https://hackerone.com/reports/974892) -- Helium | $250 | Business Logic Errors | 74up
- [Availability Impact from Exploiting Project Name Vulnerabilities](https://hackerone.com/reports/2801036) -- Doppler | $250 | Business Logic Errors | 71up
- [Bypassing x profile verification to receive instant blue checkmark and unlimited profile changes](https://hackerone.com/reports/2257374) -- X / xAI | $250 | Business Logic Errors | 60up
- [IDOR to cancel any table booking and leak sensitive information such as email,mobile number,uuid](https://hackerone.com/reports/265258) -- Eternal | $250 | Insecure Direct Object Reference (IDOR) | 41up
- [removed user can still join the organization](https://hackerone.com/reports/976441) -- New Relic | $250 | Business Logic Errors | 36up
- [Business Logic Flaw in the subscription of the app](https://hackerone.com/reports/1505189) -- Kraden | $250 | Business Logic Errors | 31up
- [Race condition on https://judge.me/people](https://hackerone.com/reports/1566017) -- Judge.me | $250 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | 26up
- [cd=false (DNSSEC) not respected in DNS over HTTPS JSON requests](https://hackerone.com/reports/1724464) -- Cloudflare Public Bug Bounty | $250 | Business Logic Errors | 23up
- [Race Condition in Oauth 2.0 flow can lead to malicious applications create multiple valid sessions](https://hackerone.com/reports/699112) -- Razer | $250 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | 8up
- [Race condition when redeeming coupon codes](https://hackerone.com/reports/59179) -- Dropbox | $216 | 5up
- [WordPress Plugin Update Confusion at trafficfactory.com](https://hackerone.com/reports/1364851) -- Traffic Factory | $200 | Business Logic Errors | 70up
- [Получение стикеров](https://hackerone.com/reports/1035320) -- VK.com | $200 | Business Logic Errors | 19up
- [Approval app's file-freshness check can be bypassed by omitting the etag parameter, allowing approval of unreviewed file changes](https://hackerone.com/reports/3610332) -- Nextcloud | $150 | Business Logic Errors | 62up
- [Race condition while removing the love react in community files.](https://hackerone.com/reports/996141) -- Figma | $150 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | 45up
- [HTML injection in an email [delivery.city-mobil.ru]](https://hackerone.com/reports/1034317) -- Mail.ru | $150 | Business Logic Errors | 8up
- [Возможность создать канал в группе, в которой пользователь не является админом [my.games]](https://hackerone.com/reports/972374) -- Mail.ru | $150 | Business Logic Errors | 7up
- [kds.ucs.ru - раскрытие информации.](https://hackerone.com/reports/1073551) -- Mail.ru | $150 | Business Logic Errors | 3up
- [IDOR Payments Status](https://hackerone.com/reports/1538669) -- Omise | $100 | Business Logic Errors | 37up
- [Price manipulation via fraction values (Parameter Tampering)](https://hackerone.com/reports/388564) -- Shipt | $100 | 34up
- [Unrestricted file upload on the image of contacts](https://hackerone.com/reports/808287) -- Nextcloud | $100 | Business Logic Errors | 24up
- [bypass forced password protection via circles app](https://hackerone.com/reports/1406926) -- Nextcloud | $100 | Business Logic Errors | 14up
- [No rate limit on Reporting a Threat on [https://community.coloros.com] lead to Increase in the User Group/Points](https://hackerone.com/reports/887684) -- OPPO | $100 | Business Logic Errors | 14up
- [Forbidden access to https://apps-staging.pingone.com but "/packages.json" visible and full path disclosure](https://hackerone.com/reports/770711) -- Ping Identity | $100 | Improper Access Control - Generic | 14up
- [Отправляем смс на любой номер от имени vk.com.  (Сообщение в смс всегда одно и то же, его менять нельзя.)](https://hackerone.com/reports/1115759) -- VK.com | $100 | Business Logic Errors | 13up
- [Bypassing Business ID/VAT # validation during registration to create accounts with duplicate Business ID/VAT #](https://hackerone.com/reports/980898) -- Visma Public | $100 | Business Logic Errors | 13up