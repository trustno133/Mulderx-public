# Session -- Top 42 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [CVE-2023-40273: Session fixation in Apache Airflow web interface](https://hackerone.com/reports/2121960) -- Internet Bug Bounty | $540 | Session Fixation | 26up
  > The session fixation vulnerability allowed the authenticated user to continue accessing Airflow webserver even after the password of the user has been reset by the admin - up until the expiry of the session of the user. Other than manually cleaning the session database (for database session backend), or changing the secure_key and restarting the webserver, there were no mechanisms to...
- [Session Fixation](https://hackerone.com/reports/18501) -- WePay | $500 | 4up
- [Session fixation on public talk links](https://hackerone.com/reports/1181962) -- Nextcloud | $100 | Session Fixation | 23up
  > 1. userA shares a talk room and protects it with a password 2. userB opens links but doesn't enter the password yet 3. Attacker steals the cookies from userB 4. userB logs in 5. attacker is now also able to read the conversation etc  ## Impact  In short the attacker is able to take over the session of the guest userB on this talk room.  The session id should be renewed once the password is...
- [Session fixation in wepay.com](https://hackerone.com/reports/14552) -- WePay | $100 | Violation of Secure Design Principles | 2up
- [2FA Session not expires after the password reset](https://hackerone.com/reports/486693) -- Nextcloud | $50 | Session Fixation | 35up
  > A bug in Nextcloud Server 15.0.2 causes pending 2FA logins to not be correctly expired when the password of the user is reset.
- [Session Fixation](https://hackerone.com/reports/135797) -- Enter | $50 | Violation of Secure Design Principles | 12up
  > Summary -------------  Your login flow is vulnerable to session fixation. This can allow an attacker to steal a valid user session from a victim.  Steps to reproduce --------------  1. As the attacker go to https://wallet.sandbox.romit.io (but do not login!) and check the cookies `romit.sandbox.session` and `SANDBOX-XSRF-TOKEN`, that are set. For example:     ...
- [H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com](https://hackerone.com/reports/423136) -- Shopify | Session Fixation | 144up
  > *Note: This report was submitted during our [H1-514 live hacking event](https://www.hackerone.com/blog/Shopify-Awards-116000-Hackers-Canada-h1-514-Recap), which had an expanded scope compared to our public bug bounty program. Some of the apps mentioned in this report are not currently in scope for our public program.*  @filedescriptor noticed that several add-on applications built by Shopify...
- [account takeover https://idea.qiwi.com/](https://hackerone.com/reports/464426) -- QIWI | Session Fixation | 87up
- [Session Persistence Designed to Keep Users Logged In Across Multiple Devices (Intended Behaviour)](https://hackerone.com/reports/3161827) -- Shopify | Session Fixation | 63up
  > This report identified a session management behavior in Shopify where, after logging out, the session associated with a user is not immediately invalidated on the server side. The researcher demonstrated the ability to reuse session cookies after logout, potentially allowing an attacker to regain access to the account if they possess the session cookie prior to logout.  The concern raised was...
- [curl Missing Sec-WebSocket-Accept Verification Enables MITM WebSocket Session Hijacking](https://hackerone.com/reports/3917775) -- curl | Man-in-the-Middle | 37up
  > ## Summary  curl's `Curl_ws_accept()` function in `lib/ws.c` processes the 101 Switching Protocols response to a client WebSocket upgrade request. RFC 6455 Section 4.1 mandates that the client MUST verify the `Sec-WebSocket-Accept` response header by computing the SHA-1 hash of the concatenation of the `Sec-WebSocket-Key` value with the magic GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`,...
- [Broken Authentication Session Token Bug](https://hackerone.com/reports/948345) -- Courier | Insufficient Session Expiration | 35up
  > Hi Team  Hope your are good I have found a broken authentication issue in https://www.trycourier.app  Steps to reproduce   1. Create a courier account or use existing one. 2. Confirm Your email address. 3. Now log out from your account and request for password reset code for your account . 4. Don't use the code that has been sent to your email address. 5. In new tab or new browser log in back...
- [Session Hijacking leads to full control of account by attacker](https://hackerone.com/reports/1201396) -- UPchieve | 21up
  > Hi Team ,  I am Samprit Das MCEH (Metaxone Certified Ethical Hacker) and a Security Researcher I just checked your website and got a critical vulnerability please read the report carefully.  Description:- The Session Hijacking attack consists of the exploitation of the web session control mechanism, which is normally managed for a session token. Because http communication uses many different...
- [Session fixation in password protected public download.](https://hackerone.com/reports/237184) -- Nextcloud | Session Fixation | 20up
  > Public downloads protected with a password are vulnerable to a session fixation attack. This finding was discovered during a penetration test of NextCloud version 10.0.2.7.  1) Pre-provision a victim with the attacker controlled cookie values:  Firefox cookie...
- [Intercom chat session information persists after logout](https://hackerone.com/reports/249798) -- Legal Robot | Session Fixation | 20up
  > A security researcher discovered that the Intercom chat session was not explicitly cleared when a user logs out. On a shared computer, this could have led to chat information from a previous session being accessible to another user because the Intercom components do not explicitly require a user to be logged in. However, this is considered low risk since an attacker would require script access...
- [Blind stored XSS due to insecure contact form at https://www.topcoder.com leads to leakage of session token and other PII](https://hackerone.com/reports/878145) -- Lab45 | Cross-site Scripting (XSS) - Stored | 19up
  > ## Summary: I have discovered a blind stored cross site scripting vulnerability due to an insecure Contact form available here https://www.topcoder.com/contact-us/ This form does not properly sanitize user input allowing for the insertion and submission of dangerous characters such as angle brackets.  I was able to submit a blind xss payload through the form which was triggered in backend...

---

- [Broken Authentication – Session Token bug](https://hackerone.com/reports/400826) -- Weblate | 18up
- [Blind stored XSS due to insecure contact form at https://█████.mil leads to leakage of session token and](https://hackerone.com/reports/1036877) -- U.S. Dept Of Defense | Cross-site Scripting (XSS) - Stored | 16up
- [Privilege Escalation: From operator to ubnt (and root) with non-interactive Session Hijacking](https://hackerone.com/reports/241044) -- Ubiquiti Inc. | 16up
- [SSL expired subdomain leads to API swap with main and flagged cookies. Unable to log device ids and certain session tokens.](https://hackerone.com/reports/1024880) -- Basecamp | Improper Restriction of Authentication Attempts | 15up
- [Pending MFA logins aren't immediatly expired after a password change](https://hackerone.com/reports/743518) -- Moneybird | Session Fixation | 15up
- [Session Fixiation allow attacker to create new evil workspace without being logged in [ Insecure Session management  ]](https://hackerone.com/reports/1329434) -- Courier | Session Fixation | 12up
- [Session Hijack via Self-XSS](https://hackerone.com/reports/962902) -- Rocket.Chat | Cross-site Scripting (XSS) - DOM | 11up
- [The session token in the URL](https://hackerone.com/reports/341372) -- Nextcloud | Information Disclosure | 11up
- [Session Hijacking](https://hackerone.com/reports/167460) -- New Relic | Improper Authentication - Generic | 10up
- [Session Hijacking attack (Different Scenario)](https://hackerone.com/reports/19640) -- HackerOne | Improper Authentication - Generic | 10up
- [Session Fixation At Logout /Session Misconfiguration](https://hackerone.com/reports/193556) -- Gratipay | Improper Authentication - Generic | 8up
- [████████ portal is open to enumeration once authenticated.  Session ID's appear static.  All PII available once a valid session ID is found.](https://hackerone.com/reports/1150573) -- U.S. Dept Of Defense | Session Fixation | 7up
- [The auth token does not expire on logging out and even after logging out all sessions](https://hackerone.com/reports/247721) -- Mail.ru | Session Fixation | 7up
- [Password Reset page Session Fixation](https://hackerone.com/reports/255020) -- Legal Robot | Session Fixation | 7up
- [Session Fixation disclosing email address](https://hackerone.com/reports/2582) -- Slack | Information Disclosure | 7up
- [Session Fixation on Acronis](https://hackerone.com/reports/1486341) -- Acronis | Session Fixation | 6up
- [Privilege Escalation with Session Hijacking Having a Non-privileged Valid User](https://hackerone.com/reports/242407) -- Ubiquiti Inc. | 6up
- [Session Token is not Verified while changing Account Setting's which Result In account Takeover](https://hackerone.com/reports/6907) -- IRCCloud | Cross-Site Request Forgery (CSRF) | 5up
- [Session Fixation Found](https://hackerone.com/reports/6504) -- ReddAPI | 5up
- [New Relic - Session Hijacking](https://hackerone.com/reports/137480) -- New Relic | 3up
- [Session Token is not Verified while changing Account Setting's which Result In account Takeover](https://hackerone.com/reports/15476) -- FanFootage | Cross-Site Request Forgery (CSRF) | 3up
- [Cookie injection from non-secure context](https://hackerone.com/reports/1560324) -- curl | Session Fixation | 2up
- [Session Token in URL](https://hackerone.com/reports/1197078) -- Sifchain | Improper Authentication - Generic | 1up
- [Broken Authentication and Session Management(Session Fixation)](https://hackerone.com/reports/167698) -- Boozt Fashion AB | Improper Authentication - Generic | 1up
- [Possible User Session Hijack using Invalid HTTPS certificate on inside.gratipay.com domain](https://hackerone.com/reports/242622) -- Gratipay | Violation of Secure Design Principles | 1up
- [Possible user session hijack by invalid HTTPS certificate on inside.gratipay.com domain](https://hackerone.com/reports/241892) -- Gratipay | Violation of Secure Design Principles | 1up
- [Broken Authentication – Session Token bug](https://hackerone.com/reports/39203) -- WePay | UI Redressing (Clickjacking)