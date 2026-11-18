# Prototype Pollution -- Top 55 reportes H1

_Generado el 2026-10-30 | Ordenado por bounty/upvotes_


- [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1106238) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 58up
  > ## Prologue  Gitlab supports Mermaid as part of GFM to allow users to generate diagrams and flowcharts from text.  In version 8.6.0, Mermaid added a support of directives to add more controll over styles(themes) applied to the diagrams.  You can read more about how this works here: https://mermaid-js.github.io/mermaid/diagrams-and-syntax-and-examples/directives.html  Syntax for declaring the...
- [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1280002) -- GitLab | $3,000 | Cross-site Scripting (XSS) - Stored | 48up
  > ### Summary  I am continue investigating #1106238 and found additional vector for prototype pollution and stored xss.  ### Steps to reproduce  1. Create an issue in any repository 2. Create mermaid diagram with following payload: ``` %%{init: { '__proto__': {'template': '<iframe xmlns=\"http://www.w3.org/1999/xhtml\" srcdoc=\"&lt;script...
- [Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)](https://hackerone.com/reports/998398) -- Elastic | Cross-site Scripting (XSS) - DOM | 157up
  > **Summary:**  deparam function which parses location.hash in https://s.swiftypecdn.com/install/v2/st.js  is vulnerable to prototype pollution. There is a script gadget in the same js file which leads to XSS.   ## Steps To Reproduce: Visit (Refresh if you don't see a pop up) https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)  ## Root Cause https://s.swiftypecdn.com/install/v2/st.js...
- [property-expr - Prototype pollution](https://hackerone.com/reports/910206) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 33up
  > I would like to report Prototype pollution in property-expr It allows attacker to modify the prototype of a base object.  # Module  **module name:** property-expr **version:** 2.0.2 **npm page:** `https://www.npmjs.com/package/property-expr`  ## Module Description  > Tiny property path utilities, including path parsing and metadata and deep property setters and getters  ## Module Stats  >...
- [Denial of Service via `__proto__` header name in `req.headersDistinct` (Uncaught `TypeError` crashes Node.js process)](https://hackerone.com/reports/3560402) -- Node.js | Uncontrolled Resource Consumption | 22up
  > A flaw in Node.js HTTP request handling causes an uncaught `TypeError` when a request is received with a header named `__proto__` and the application accesses `req.headersDistinct`.  When this occurs, `dest["__proto__"]` resolves to `Object.prototype` rather than `undefined`, causing `.push()` to be called on a non-array. This exception is thrown synchronously inside a property getter and...
- [Prototype pollution attack (lodash)](https://hackerone.com/reports/712065) -- Node.js third-party modules | Allocation of Resources Without Limits or Throttling | 20up
  > I would like to report a prototype pollution vulnerability in lodash. It allows an attacker to inject properties on Object.prototype  Module module name: lodash version: 4.17.15 npm page: https://www.npmjs.com/package/lodash  Module Description The Lodash library exported as Node.js modules.  Module Stats 25,228,177 downloads in the last week  Vulnerability Vulnerability Description This is a...
- [Jitsi: Bridge Message Spoofing due to Improper JSON Handling leads to Prototype Pollution](https://hackerone.com/reports/2095061) -- 8x8 | Command Injection - Generic | 17up
  > The Jitsi VideoBridge failed to properly handle JSON messages with duplicate `colibriClass` keys, enabling clients to send messages interpreted differently by the bridge and resulting in unauthorized actions within video conferences.  Jitsi Security Advisory has been published: https://github.com/jitsi/security-advisories/blob/master/advisories/JSA-2023-0001.md  Changes: * (lib-jitsi-meet)...
- [Prototype pollution via console.table properties](https://hackerone.com/reports/1431042) -- Node.js | Modification of Assumed-Immutable Data (MAID) | 16up
  > **Summary:**  Attacker control of the second `properties` parameter of `console.table` may lead to prototype pollution.  **Description:**  Due to the formatting logic of the `console.table` function it is not safe to allow user controlled input to be passed to the `properties` parameter while simultaneously passing a plain object with at least one property as the first parameter.  The prototype...
- [Prototype pollution attack (lodash / constructor.prototype)](https://hackerone.com/reports/380873) -- Node.js third-party modules | Uncontrolled Resource Consumption | 15up
  > I would like to report a prototype pollution vulnerability in lodash. It allows an attacker to inject properties on Object.prototype.  # Module  **module name:** lodash **version:** 4.17.10 **npm page:** `https://www.npmjs.com/package/lodash`  ## Module Description  The Lodash library exported as Node.js modules.  ## Module Stats  12M downloads in the last week  # Vulnerability  ##...
- [[nested-property] Prototype Pollution](https://hackerone.com/reports/788883) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 14up
  > Hi team, I would like to report a prototype pollution vulnerability in nested-property that allows an attacker to modify properties on Object.prototype.  Module name:nested-property version: 1.0.4 npm page: https://www.npmjs.com/package/nested-property  Module Description Read, write or test a data structure's nested property via a string like 'my.nested.property'. It works through arrays and...
- [[i18next] Prototype pollution attack](https://hackerone.com/reports/968355) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 11up
  > I would like to report a prototype pollution vulnerability in i18next. It allows to modify the prototype of a base object, which may result in DoS, XSS, RCE, etc. depending on the way the library is used.  # Module  **module name:** i18next **version:** 19.7.0 **npm page:** ` https://www.npmjs.com/package/i18next`  ## Module Description  i18next is a very popular internationalization framework...
- [Prototype pollution in multipart parsing](https://hackerone.com/reports/804772) -- Node.js third-party modules | Uncontrolled Resource Consumption | 11up
  > I would like to report a prototype pollution attack in fastify-multipart it allows to crash a remote server parsing multipart requests by sending a specially crafted request.  # Module  **module name:** fastify-multipart **version:** all versions before < v1.0.5. v1.0.5 contains the fix.  **npm page:** `https://www.npmjs.com/package/fastify-multipart`  ## Module...
- [Prototype pollution attack (lodash)](https://hackerone.com/reports/310443) -- Node.js third-party modules | Uncontrolled Resource Consumption | 11up
  > As discussed in #309391, here's the separate report for each of the library. This one is the information for the lodash library.  **Module:**  [lodash](https://www.npmjs.com/package/lodash)  **Summary:**  Utilities function in all the listed modules can be tricked into modify the prototype of "Object" when the attacker control part of the structure passed to these function. This can let an...
- [Prototype pollution in dot-prop](https://hackerone.com/reports/719856) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 10up
  > I would like to report a parameter pollution in dot-prop It allows an attacker to modify the prototype of a base object which can vary in severity depending on the implementation (DoS, access to sensitive data, RCE).  # Module  **module name:** dot-prop **version:** 5.1.1 **npm page:** https://www.npmjs.com/package/dot-prop  ## Module Description  Get, set, or delete a property from a nested...
- [Prototype Pollution lodash 4.17.15](https://hackerone.com/reports/864701) -- Node.js third-party modules | Uncontrolled Resource Consumption | 9up
  > I would like to report Prototype Pollution in lodash version 4.17.15 It allows Denial of Service and more.   # Module **module name:** lodash **version:** 4.17.15 **npm page:** `https://www.npmjs.com/package/lodash`  ## Module Description  The Lodash library exported as Node.js modules.  ## Module Stats  27M in the last week  # Vulnerability  ## Vulnerability Description  ## Steps To...

---

- [Prototype pollution attack (merge.recursive)](https://hackerone.com/reports/381194) -- Node.js third-party modules | Uncontrolled Resource Consumption | 9up
- [The use of __proto__ in process.mainModule.__proto__.require() bypasses the permission system in Node v19.6.1](https://hackerone.com/reports/1877919) -- Node.js | Privilege Escalation | 8up
- [SQL Injection or Denial of Service due to a Prototype Pollution](https://hackerone.com/reports/869574) -- Node.js third-party modules | SQL Injection | 8up
- [Prototype pollution attack through jQuery $.extend](https://hackerone.com/reports/454365) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 8up
- [[klona] Prototype pollution](https://hackerone.com/reports/778414) -- Node.js third-party modules | 7up
- [Prototype pollution attack (defaults-deep / constructor.prototype)](https://hackerone.com/reports/380878) -- Node.js third-party modules | Uncontrolled Resource Consumption | 7up
- [Prototype pollution attack (lutils-merge)](https://hackerone.com/reports/439107) -- Node.js third-party modules | Uncontrolled Resource Consumption | 6up
- [Prototype Pollution Vulnerability in mpath Package](https://hackerone.com/reports/390860) -- Node.js third-party modules | 6up
- [[json8-merge-patch] Prototype Pollution](https://hackerone.com/reports/980649) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 5up
- [[extend-merge] Prototype pollution](https://hackerone.com/reports/878339) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 5up
- [Prototype pollution attack (extend)](https://hackerone.com/reports/381185) -- Node.js third-party modules | Uncontrolled Resource Consumption | 5up
- [Prototype Pollution Vulnerability in noble Package](https://hackerone.com/reports/390857) -- Node.js third-party modules | 4up
- [[utils-extend] Prototype pollution](https://hackerone.com/reports/801522) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 4up
- [Prototype pollution attack (upmerge)](https://hackerone.com/reports/439120) -- Node.js third-party modules | 4up
- [Prototype pollution attack in just-extend](https://hackerone.com/reports/430291) -- Node.js third-party modules | Uncontrolled Resource Consumption | 4up
- [Prototype pollution attack (deep-extend)](https://hackerone.com/reports/311333) -- Node.js third-party modules | 4up
- [Prototype pollution attack (assign-deep)](https://hackerone.com/reports/310707) -- Node.js third-party modules | Uncontrolled Resource Consumption | 4up
- [Prototype pollution attack (mixin-deep)](https://hackerone.com/reports/311236) -- Node.js third-party modules | Uncontrolled Resource Consumption | 4up
- [Prototype pollution attack (Hoek)](https://hackerone.com/reports/310439) -- Node.js third-party modules | Uncontrolled Resource Consumption | 4up
- [Child process environment injection via prototype pollution](https://hackerone.com/reports/878181) -- Node.js | Code Injection | 3up
- [Prototype pollution attack in node.extend](https://hackerone.com/reports/430831) -- Node.js third-party modules | Uncontrolled Resource Consumption | 3up
- [Prototype pollution attack (defaults-deep)](https://hackerone.com/reports/310514) -- Node.js third-party modules | Uncontrolled Resource Consumption | 3up
- [Prototype pollution attack (merge-deep)](https://hackerone.com/reports/310708) -- Node.js third-party modules | Uncontrolled Resource Consumption | 3up
- [[plain-object-merge] Prototype pollution](https://hackerone.com/reports/871156) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 2up
- [Prototype pollution attack (smart-extend)](https://hackerone.com/reports/438274) -- Node.js third-party modules | 2up
- [Prototype pollution attack (mergify)](https://hackerone.com/reports/439098) -- Node.js third-party modules | 2up
- [Prototype pollution attack (deap)](https://hackerone.com/reports/310446) -- Node.js third-party modules | 2up
- [[chart.js] Prototype pollution](https://hackerone.com/reports/776371) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 1up
- [[ts-dot-prop] Prototype Pollution](https://hackerone.com/reports/980599) -- Node.js third-party modules | 1up
- [[objtools] Prototype pollution](https://hackerone.com/reports/878394) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 1up
- [[keyd] Prototype pollution](https://hackerone.com/reports/877515) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 1up
- [[json-bigint] DoS via `__proto__` assignment](https://hackerone.com/reports/916430) -- Node.js third-party modules | Uncontrolled Resource Consumption | 1up
- [Prototype pollution attack (lodash)](https://hackerone.com/reports/841380) -- Node.js third-party modules | Uncontrolled Resource Consumption | 1up
- [[supermixer] Prototype pollution](https://hackerone.com/reports/959987) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID) | 1up
- [Prototype Pollution Vulnerability in cached-path-relative Package](https://hackerone.com/reports/390847) -- Node.js third-party modules | Uncontrolled Resource Consumption | 1up
- [Prototype pollution attack (merge-objects)](https://hackerone.com/reports/310706) -- Node.js third-party modules | 1up
- [Prototype pollution attack (merge-options)](https://hackerone.com/reports/311336) -- Node.js third-party modules | 1up
- [Prototype pollution attack (merge-recursive)](https://hackerone.com/reports/311337) -- Node.js third-party modules | 1up
- [[@firebase/util] Prototype pollution](https://hackerone.com/reports/1001218) -- Node.js third-party modules
- [[object-path-set] Prototype pollution](https://hackerone.com/reports/878332) -- Node.js third-party modules | Modification of Assumed-Immutable Data (MAID)