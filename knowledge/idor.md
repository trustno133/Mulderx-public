# IDOR / BAC / BOLA -- Top 100 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Account Takeover via Password Reset without user interactions](https://hackerone.com/reports/2293343) -- GitLab | $35,000 | Improper Access Control - Generic | 984up
  > @asterion04 submitted a report to GitLab.  Summary  I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address. Steps to reproduce  Go to "Forgot Your Password?" link Enter the victim's email and intercept the submit request via Burp Suite . Then right-click on the...
- [RepositoryPipeline allows importing of local git repos](https://hackerone.com/reports/1685822) -- GitLab | $22,300 | Improper Access Control - Generic | 88up
  > ### Summary  When importing a project via the BulkImports, the response field `httpUrlToRepo` from the client is used to fetch the repo:  https://gitlab.com/gitlab-org/gitlab/-/blob/v15.3.1-ee/lib/bulk_imports/projects/pipelines/repository_pipeline.rb#L17 ```ruby         def load(context, data)           url = data['httpUrlToRepo']           return unless url.present?            url =...
- [access list owner can escalate his role to the highest roles](https://hackerone.com/reports/2281075) -- Teleport | $21,000 | Privilege Escalation | 255up
- [Getting all the CD keys of any game](https://hackerone.com/reports/391217) -- Valve | $20,000 | Improper Access Control - Generic | 638up
  > Using the `/partnercdkeys/assignkeys/` endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access. Audit logs were not bypassed using this method, and an investigation of those audit logs did not show any prior or ongoing exploitation of this bug.
- [bd-j exploit chain](https://hackerone.com/reports/1379975) -- PlayStation | $20,000 | Privilege Escalation | 297up
  > Hey PlayStation!  Below are 5 vulnerabilities chained together that allows an attacker to gain JIT capabilities and execute arbitrary payloads. The provided payload triggers a buffer overflow that causes a kernel panic. Please consider each of the vulnerabilities individually. AFAIK, this is the first exploit chain that is being submitted to you :)  ## Vulnerabilities  ### [MEDIUM] [PS4] [PS5]...
- [Steal private objects of other projects via project import](https://hackerone.com/reports/743953) -- GitLab | $20,000 | Insecure Direct Object Reference (IDOR) | 253up
  > ### Summary An attacker could transfer issues, merge requests of another project to the imported project by importing a crafted GitLab export.   ### Steps to reproduce 1. Import the attached tarball as GitLab export. 2. Check the issues page of the imported project. You will see an private issue created by https://gitlab.com/nyangawa-h1 instead of the current user.  ### Description The exploit...
- [Private objects exposed through project import](https://hackerone.com/reports/767770) -- GitLab | $20,000 | Insecure Direct Object Reference (IDOR) | 132up
  > ### Summary This is a bypass of https://hackerone.com/reports/743953 , the current fix is blocking all "_ids" attributes. However an attacker could still set attributes like `issue_ids` by indrectly settings the field within the `attributes` field it self: ``` # project.json     "attributes": {         "issue_ids": [ 29279725 ],         "description": "Set from attributes[description]"    ...
- [Delete anyone's content spotlight remotely.](https://hackerone.com/reports/1819832) -- Snapchat | $15,000 | Insecure Direct Object Reference (IDOR) | 799up
  > Hello Snapchat,  Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat users and profit in millions. I found a way to delete anyone's spotlight remotely.  Please see the below poc:-  1. First go to https://my.snapchat.com/myposts and log in there. 2. You will see your posts . 3. Now turn burp suite and intercept. 4.Select any of your posts...
- [IDOR allows user to access report details via reference.json endpoint](https://hackerone.com/reports/3862641) -- HackerOne | $15,000 | Insecure Direct Object Reference (IDOR) | 336up
  > **Summary:** An information disclosure vulnerability on the `/reports/{id}/reference.json` endpoint allowed VDP accounts created via `hackerone.com/vdp-sign-up` to access certain private report details. While the endpoint returned HTTP 422 "You do not have the appropriate access," the error response contained additional report details in the `context.subject` field.  **Description:** By sending...
- [file read on MCS servers via supplying a QCOW2 image with external backing file](https://hackerone.com/reports/1024899) -- Mail.ru | $15,000 | Information Disclosure | 222up
- [[mcs.mail.ru] Пользователь с ролью наблюдателя может создавать ключи доступа для очереди сообщений (sqs.mcs.mail.ru)](https://hackerone.com/reports/1177451) -- Mail.ru | $15,000 | Improper Access Control - Generic | 147up
- [Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests](https://hackerone.com/reports/689314) -- GitLab | $12,000 | Privilege Escalation | 457up
  > I've found a three minor vulnerabilities which, when combined, allow an attacker to copy private repositories, confidential issues, private snippets, and then some. I'll go through the code path to explain the vulnerabilities and how they are combined. See the **Proof of Concept** section if you want to reproduce it immediately.  Let's start at the `ProjectsController` of EE, which is prepended...
- [Exfiltrate and mutate repository and project data through injected templated service](https://hackerone.com/reports/446585) -- GitLab | $11,000 | Improper Access Control - Generic | 762up
  > The GitLab import feature contains a vulnerability that allows an attacker to import a project that creates a service template. Service templates can normally only be created by a GitLab instance Administrator. When a new project is created, service templates are automatically initialized for the project that is being created. Initializing and saving the service templates is handled in the...
- [IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users](https://hackerone.com/reports/415081) -- PayPal | $10,500 | Insecure Direct Object Reference (IDOR) | 796up
  > PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single...
- [Arbitrary Read of Another Users private repository without Authorization](https://hackerone.com/reports/3124517) -- GitHub | $10,000 | Insecure Direct Object Reference (IDOR) | 276up
  > An improper access control vulnerability was identified in GitHub Enterprise Server that allowed users with access to any repository to retrieve limited code content from another repository by creating a diff between the repositories. To exploit this vulnerability, an attacker needed to know the name of a private repository along with its branches, tags, or commit SHAs that they could use to...

---

- [Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form](https://hackerone.com/reports/418767) -- HackerOne | $10,000 | Improper Authorization | 208up
- [read new emails from any inbox IOS APP in notification center](https://hackerone.com/reports/977212) -- Mail.ru | $10,000 | Insecure Direct Object Reference (IDOR) | 186up
- [Authentication bypass on gist.github.com through SSH Certificates](https://hackerone.com/reports/1901040) -- GitHub | $10,000 | Improper Access Control - Generic | 182up
- [Using gossip to drain miner wallets](https://hackerone.com/reports/1058879) -- Zilliqa | $10,000 | Improper Authorization | 111up
- [RCE hazard in reporting (via Chromium)](https://hackerone.com/reports/1168765) -- Elastic | $10,000 | Privilege Escalation | 25up
- [Cross-organization data access in city-mobil.ru](https://hackerone.com/reports/863983) -- Mail.ru | $8,000 | Improper Access Control - Generic | 374up
- [Account Takeover via billing](https://hackerone.com/reports/394329) -- Chaturbate | $8,000 | Improper Authorization | 55up
- [Exposed proxy allows to access internal reddit domains](https://hackerone.com/reports/2967634) -- Reddit | $7,500 | Improper Access Control - Generic | 295up
- [Open Selenoid instance at 188.93.63.186 leads to LFR/SSRF.](https://hackerone.com/reports/512973) -- Mail.ru | $6,000 | Improper Access Control - Generic | 93up
- [Hijack all emails sent to any domain that uses Cloudflare Email Forwarding](https://hackerone.com/reports/1419341) -- Cloudflare Public Bug Bounty | $6,000 | Improper Authorization | 76up
- [Chain of vulnerabilities in Uber for Business Vouchers program allows for attacker to perform arbitrary charges to victim's U4B payment account](https://hackerone.com/reports/1145428) -- Uber | $5,750 | Insecure Direct Object Reference (IDOR) | 58up
- [Kroki Arbitrary File Read/Write](https://hackerone.com/reports/1098793) -- GitLab | $5,600 | Improper Access Control - Generic | 41up
- [Discoverability by phone number/email restriction bypass](https://hackerone.com/reports/1439026) -- X / xAI | $5,040 | Improper Access Control - Generic | 216up
- [Deleting all DMs on RedditGifts.com](https://hackerone.com/reports/1213237) -- Reddit | $5,000 | Insecure Direct Object Reference (IDOR) | 267up
- [Linux privilege escalation via trusted $PATH in keybase-redirector](https://hackerone.com/reports/426944) -- Keybase | $5,000 | Privilege Escalation | 245up
- [Able to bypass email verification and change email to any other user email](https://hackerone.com/reports/1551176) -- Reddit | $5,000 | Improper Access Control - Generic | 200up
- [IDOR on GraphQL queries BillingDocumentDownload and BillDetails](https://hackerone.com/reports/2207248) -- Shopify | $5,000 | Insecure Direct Object Reference (IDOR) | 187up
- [Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability](https://hackerone.com/reports/1658418) -- Reddit | $5,000 | Insecure Direct Object Reference (IDOR) | 163up
- [CVE-2023-5528: Insufficient input sanitization in in-tree storage plugin leads to privilege escalation on Windows nodes](https://hackerone.com/reports/2231019) -- Kubernetes | $5,000 | Code Injection | 67up
- [Possible access to the car's photo and registration by its ID on [fleet.city-mobil.ru]](https://hackerone.com/reports/950507) -- Mail.ru | $5,000 | Insecure Direct Object Reference (IDOR) | 31up
- [Remote Code Execution in coming Kibana 7.7.0](https://hackerone.com/reports/861744) -- Elastic | $5,000 | Privilege Escalation | 14up
- [important: Apache HTTP Server weakness with encoded question marks in backreferences (CVE-2024-38474)](https://hackerone.com/reports/2585381) -- Internet Bug Bounty | $4,920 | Improper Input Validation | 51up
- [important: Apache HTTP Server may use exploitable/malicious backend application output to run local handlers via internal redirect (CVE-2024-38476)](https://hackerone.com/reports/2585376) -- Internet Bug Bounty | $4,920 | Inclusion of Functionality from Untrusted Control Sphere | 31up
- [Unauthorized access to █████████.com allows access to Uber Brazil tax documents and system.](https://hackerone.com/reports/530441) -- Uber | $4,500 | Improper Access Control - Generic | 210up
- [DNS rebinding in --inspect (insufficient fix of CVE-2022-32212 affecting macOS devices)](https://hackerone.com/reports/1714979) -- Internet Bug Bounty | $4,200 | Improper Access Control - Generic | 47up
- [Access to Tarantool](https://hackerone.com/reports/722337) -- Mail.ru | $4,000 | Improper Access Control - Generic | 155up
- [Insufficient Type Check on GraphQL leading to Maintainer delete repository](https://hackerone.com/reports/858671) -- GitLab | $4,000 | Improper Access Control - Generic | 18up
- [Improper Access Control + Financial fraud allows attacker to disclose + add arbitrary products to another's user's order](https://hackerone.com/reports/1903322) -- Shipt | $3,900 | Improper Access Control - Generic | 79up
- [Claiming the listing of a non-delivery restaurant through OTP manipulation](https://hackerone.com/reports/1330529) -- Eternal | $3,250 | Improper Authorization | 108up
- [Email change or personal data change on the account.](https://hackerone.com/reports/1250037) -- Stripe | $3,000 | Insecure Direct Object Reference (IDOR) | 149up
- [[api.pandao.ru] IDOR for order delivery address](https://hackerone.com/reports/723461) -- Mail.ru | $3,000 | Insecure Direct Object Reference (IDOR) | 125up
- [Initial mirror user can be assigned by other user even if the mirror was removed](https://hackerone.com/reports/819821) -- GitLab | $3,000 | Improper Access Control - Generic | 4up
- [Admin panel Exposure without credential at https://plus-website.shopifycloud.com/admin.php](https://hackerone.com/reports/1417288) -- Shopify | $2,900 | Improper Access Control - Generic | 109up
- [[IDOR] Improper Access Control on Embedded Submission Form](https://hackerone.com/reports/2483666) -- HackerOne | $2,500 | Insecure Direct Object Reference (IDOR) | 110up
- [PS4 BD-J privilege escalation using nested JAR](https://hackerone.com/reports/3452696) -- PlayStation | $2,500 | Privilege Escalation | 85up
- [IDOR the ability to view support tickets of any user on seller platform](https://hackerone.com/reports/1392630) -- TikTok | $2,500 | Insecure Direct Object Reference (IDOR) | 74up
- [Privilege Escalation in kOps using GCE/GCP Provider](https://hackerone.com/reports/1842829) -- Kubernetes | $2,500 | Privilege Escalation | 52up
- [Proper verification is not done before sending invitations to researchers for certain private programs with rules e.g. "Participants must be US-based"](https://hackerone.com/reports/427502) -- HackerOne | $2,500 | Improper Access Control - Generic | 43up
- [Access to information about any video and its owner via GraphQL endpoint [dictor.mail.ru]](https://hackerone.com/reports/924914) -- Mail.ru | $2,500 | Insecure Direct Object Reference (IDOR) | 42up
- [[NR Insights] Pull any Insights/NRQL data from any NR account](https://hackerone.com/reports/397137) -- New Relic | $2,500 | Insecure Direct Object Reference (IDOR) | 37up
- [[NR Insights] IDOR - Modify the filter settings for any NR Insights dashboard through internal_api endpoint](https://hackerone.com/reports/459443) -- New Relic | $2,500 | Insecure Direct Object Reference (IDOR) | 28up
- [Возможность изменить поле "E-Mail для доступа в личный кабинет" у другого пользователя [corporate.city-mobil.ru]](https://hackerone.com/reports/956791) -- Mail.ru | $2,500 | Improper Access Control - Generic | 21up
- [Ingress-nginx path allows retrieval of ingress-nginx serviceaccount token](https://hackerone.com/reports/1382919) -- Kubernetes | $2,500 | Privilege Escalation | 17up
- [Privilege Escalation through Keybase Installer via Helper](https://hackerone.com/reports/473252) -- Keybase | $2,500 | Privilege Escalation | 17up
- [Unauthorized access to all collections, products, pages from other stores](https://hackerone.com/reports/93921) -- Shopify | $2,500 | Improper Authentication - Generic | 6up
- [unauthorized access to all customers first and last name](https://hackerone.com/reports/92453) -- Shopify | $2,500 | Improper Authentication - Generic | 4up
- [Airflow Daemon Mode Insecure Umask Privilege Escalation](https://hackerone.com/reports/1690093) -- Internet Bug Bounty | $2,400 | Incorrect Permission Assignment for Critical Resource | 8up
- [Stealing Users OAuth authorization code via redirect_uri](https://hackerone.com/reports/1861974) -- pixiv | $2,000 | Improper Authorization | 253up
- [Worker container escape lead to arbitrary file reading in host machine [again]](https://hackerone.com/reports/697055) -- Semmle | $2,000 | Privilege Escalation | 178up
- [Undocumented `fileCopy` GraphQL API](https://hackerone.com/reports/981472) -- Shopify | $2,000 | Improper Access Control - Generic | 157up
- [Worker container escape lead to arbitrary file reading in host machine](https://hackerone.com/reports/694181) -- Semmle | $2,000 | Privilege Escalation | 112up
- [Ability to publish a paid theme without purchasing it.](https://hackerone.com/reports/953083) -- Shopify | $2,000 | Improper Access Control - Generic | 90up
- [Attacker can use any non-enabled capability](https://hackerone.com/reports/2930811) -- Cosmos | $2,000 | Privilege Escalation | 81up
- [Improper authorization allows disclosing users' notification data in Notification channel server](https://hackerone.com/reports/1314162) -- LY Corporation | $2,000 | Improper Authorization | 78up
- [Parental Pin Bypass](https://hackerone.com/reports/1077520) -- Showmax | $2,000 | Privilege Escalation | 75up
- [CI for [example.gov] can be logged in and accessible](https://hackerone.com/reports/311289) -- GSA Bounty | $2,000 | Improper Access Control - Generic | 49up
- [Authentication Bypass with usage of PreSignedURL](https://hackerone.com/reports/2337427) -- ownCloud | $2,000 | Improper Access Control - Generic | 44up
- [Выполнение API-методов при открытии сообщества/приложения](https://hackerone.com/reports/1354452) -- VK.com | $2,000 | Privilege Escalation | 43up
- [Ability to publish a paid theme without purchasing it.](https://hackerone.com/reports/927567) -- Shopify | $2,000 | Improper Access Control - Generic | 21up
- [Argo CD reconciles apps outside configured namespaces when sharding is enabled](https://hackerone.com/reports/1847140) -- Internet Bug Bounty | $2,000 | Improper Access Control - Generic | 18up
- [Possible to make restricted files public on Phabricator via Diffusion](https://hackerone.com/reports/1560717) -- Phabricator | $2,000 | Improper Access Control - Generic | 17up
- [Ability to view monitor names of other NR accounts through internal API (v3) via "monitor_id" parameter](https://hackerone.com/reports/462321) -- New Relic | $2,000 | Insecure Direct Object Reference (IDOR) | 8up
- [unauthorized access to all collections name](https://hackerone.com/reports/93004) -- Shopify | $2,000 | Privilege Escalation | 2up
- [Collaborators and Staff members without all necessary permissions are able to create, edit and install custom apps](https://hackerone.com/reports/1555502) -- Shopify | $1,900 | Improper Access Control - Generic | 46up
- [Low Privileged Staff Member Can Export Billing Charges](https://hackerone.com/reports/1010835) -- Shopify | $1,900 | Improper Access Control - Generic | 24up
- [Attacker is able to create,Edit & delete notes and leak the title of a victim's private personal snippet](https://hackerone.com/reports/1751258) -- GitLab | $1,730 | Insecure Direct Object Reference (IDOR) | 29up
- [`account_info.read` scope OAuth app access token can change token owner's account name.](https://hackerone.com/reports/1031240) -- Dropbox | $1,728 | Improper Access Control - Generic | 34up
- [Gitlab Pages token theft using service workers](https://hackerone.com/reports/1439552) -- GitLab | $1,680 | Improper Authorization | 14up
- [TikTok 2FA Bypass](https://hackerone.com/reports/1247108) -- TikTok | $1,564 | Improper Authorization | 194up
- [idor allows you to delete photos and album from a gallery](https://hackerone.com/reports/380410) -- Pornhub | $1,500 | Insecure Direct Object Reference (IDOR) | 266up
- [IDOR allows any user to edit others videos](https://hackerone.com/reports/681473) -- Pornhub | $1,500 | Insecure Direct Object Reference (IDOR) | 248up
- [Privilege escalation in workers container](https://hackerone.com/reports/692603) -- Semmle | $1,500 | Privilege Escalation | 206up
- [Apache HTTP [2.4.17-2.4.38] Local Root Privilege Escalation](https://hackerone.com/reports/520903) -- Internet Bug Bounty | $1,500 | Privilege Escalation | 121up
- [Support Portal Takeover via Leaked API KEY](https://hackerone.com/reports/1766228) -- AMBER AI | $1,500 | Improper Access Control - Generic | 90up
- [Unauthorized access to GovSlack](https://hackerone.com/reports/1758174) -- Slack | $1,500 | Improper Authentication - Generic | 81up
- [IDOR via internal_api "users" endpoint](https://hackerone.com/reports/349291) -- New Relic | $1,500 | Insecure Direct Object Reference (IDOR) | 77up
- [A staff member with no permissions can edit Store Customer Email](https://hackerone.com/reports/980511) -- Shopify | $1,500 | Insecure Direct Object Reference (IDOR) | 71up
- [Internal API endpoint discloses full account name of email address associated with unconfirmed user](https://hackerone.com/reports/332381) -- New Relic | $1,500 | Insecure Direct Object Reference (IDOR) | 63up
- [[idor] Unauthorized Read access to all the private posts(Including Photos,Videos,Gifs)](https://hackerone.com/reports/148764) -- Pornhub | $1,500 | Improper Authentication - Generic | 58up
- [HTTP Request Smuggling via Unsanitized Hop-by-Hop Headers](https://hackerone.com/reports/3622877) -- Cloudflare Public Bug Bounty | $1,500 | Improper Access Control - Generic | 51up
- [Bypass of my three other reports #267636 + #255894 + #271861 - (IDOR) Ability to see full name associated with other New Relic accounts](https://hackerone.com/reports/320173) -- New Relic | $1,500 | Insecure Direct Object Reference (IDOR) | 37up
- [IDOR - disclosure of private videos - /api_android_v3/getUserVideos](https://hackerone.com/reports/186279) -- Pornhub | $1,500 | Improper Authentication - Generic | 32up
- [Possible to enumerate Addresses of users using AddressId and guessing the delivery_subzone](https://hackerone.com/reports/514897) -- Eternal | $1,500 | Insecure Direct Object Reference (IDOR) | 29up
- [Unauthorized packages modification or secrets exfiltration via GitHub actions](https://hackerone.com/reports/1548870) -- Linux Foundation Decentralized Trust | $1,500 | Improper Access Control - Generic | 25up
- [(Pornhub & Youporn & Brazzers ANDROID APP) : Upload Malicious APK / Overrite Existing APK  / Android BackOffice Access](https://hackerone.com/reports/142352) -- Pornhub | $1,500 | Code Injection | 16up