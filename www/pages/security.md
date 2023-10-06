<!--
.. title: Security
.. slug: security
.. date: 2021-04-03 11:55:50 UTC+1
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->

# Reporting security vulnerabilities

If you think you have found a security vulnerability in Mosquitto, please
follow the steps on [Eclipse Security] page to report it.

# Past vulnerabilities

Listed with most recent first. Further information on security related issues
can be found in the [security category].

* August 2023: [CVE-2023-0809]: Fix excessive memory being allocated based on
  malicious initial packets that are not CONNECT packets. Affecting versions
  **1.5.0** to **2.0.15**. Fixed in **2.0.16**.
* August 2023: [CVE-2023-3592]: Fix memory leak when clients send v5 CONNECT
  packets with a will message that contains invalid property types. Affecting
  version **1.6.0** to **2.0.15** Fixed in **2.0.16**.
* August 2023: [CVE-2023-28366]: Clients sending unacknowledged QoS 2 messages
  with duplicate message ids cause a memory leak. Affecting versions **1.3.2**
  to **2.0.15** inclusive, fixed in **2.0.16**.
* August 2022: Deleting the anonymous group in the dynamic security plugin
  could lead to a crash. Affecting versions **2.0.0** to **2.0.14** inclusive,
  fixed in **2.0.15**.
* August 2021: [CVE-2021-34434] Affecting versions **2.0.0** to **2.0.11**
  inclusive, fixed in **2.0.12**.
* April 2021: [CVE-2021-28166] Affecting versions **2.0.0** to **2.0.9**
  inclusive, fixed in **2.0.10**.
* December 2020: Running mosquitto_passwd with the following arguments only
  `mosquitto_passwd -b password_file username password` would cause the
  username to be used as the password. Affecting versions **2.0.0** to
  **2.0.2** inclusive, fixed in **2.0.3**.
* September 2019: [CVE-2019-11779]. Affecting versions **1.5** to **1.6.5**
  inclusive, fixed in **1.6.6** and **1.5.9**. More details at [version-166-released].
* September 2019: [CVE-2019-11778]. Affecting versions **1.6** to **1.6.4**
  inclusive, fixed in **1.6.5**. More details at [version-166-released].
* April 2019: No CVE assigned. Affecting versions **1.6** and **1.6.1**,
  fixed in **1.6.2**. More details at [version-162-released].
* December 2018: [CVE-2018-20145]. Affecting versions **1.5** to **1.5.4**
  inclusive, fixed in **1.5.5.**. More details at [version-155-released].
* November 2018: No CVE assigned. Affecting versions **1.4** to **1.5.3**
  inclusive, fixed in **1.5.4**. More details at [version-154-released].
* September 2018: [CVE-2018-12543] affecting versions **1.5** to **1.5.2**
  inclusive, fixed in **1.5.3**.
* April 2018: [CVE-2017-7655] affecting versions **1.0** to **1.4.15**
  inclusive, fixed in **1.5**.
* April 2018: [CVE-2017-7654] affecting versions **1.0** to **1.4.15**
  inclusive, fixed in **1.5**.
  [security-advisory-cve-2017-7653-cve-2017-7654].
* April 2018: [CVE-2017-7653] affecting versions **1.0** to **1.4.15**
  inclusive, fixed in **1.5**.
* February 2018: [CVE-2017-7651] affecting versions **0.15** to **1.4.14**
  inclusive, fixed in **1.4.15**. More details at
  [security-advisory-cve-2017-7651-cve-2017-7652].
* February 2018: [CVE-2017-7652] affecting versions **1.0** to **1.4.14**
  inclusive, fixed in **1.4.15**. More details at
  [security-advisory-cve-2017-7651-cve-2017-7652].
* June 2017: [CVE-2017-9868] affecting versions **0.15** to **1.4.12**
  inclusive, fixed in **1.4.13**. More details at
  [security-advisory-cve-2017-9868].
* May 2017: [CVE-2017-7650] affecting versions **0.15** to **1.4.11**
  inclusive, fixed in **1.4.12**. More details at
  [security-advisory-cve-2017-7650].

[version-166-released]: /blog/2019/09/version-1-6-6-released/
[version-162-released]: /blog/2019/04/version-1-6-2-released/
[version-155-released]: /blog/2018/11/version-155-released/
[version-154-released]: /blog/2018/11/version-154-released/
[security-advisory-cve-2018-12543]: /blog/2018/09/security-advisory-cve-2018-12543/
[security-advisory-cve-2017-7651-cve-2017-7652]: /blog/2018/02/security-advisory-cve-2017-7651-cve-2017-7652/
[security-advisory-cve-2017-7650]: /blog/2017/05/security-advisory-cve-2017-7650/
[security-advisory-cve-2017-9868]: /blog/2017/06/security-advisory-cve-2017-9868/

[Eclipse Security]: https://www.eclipse.org/security/
[security category]: /blog/categories/security/

[CVE-2021-34434]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34434
[CVE-2021-28166]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28166
[CVE-2019-11779]: https://nvd.nist.gov/vuln/detail/CVE-2019-11779
[CVE-2019-11778]: https://nvd.nist.gov/vuln/detail/CVE-2019-11778
[CVE-2018-20145]: https://nvd.nist.gov/vuln/detail/CVE-2018-20145
[CVE-2018-12543]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12543
[CVE-2017-9868]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9868
[CVE-2017-7655]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7655
[CVE-2017-7654]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7654
[CVE-2017-7653]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7653
[CVE-2017-7652]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7652
[CVE-2017-7651]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7651
[CVE-2017-7650]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7650
