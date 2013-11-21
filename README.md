DKIM Verifier
=============

This is an Add-on for Mozilla Thunderbird, that verifies DKIM Signatures according to the RFC 6376.

The source code is available  at https://github.com/lieser/dkim_verifier.
A packed version can be downloaded from https://addons.mozilla.org/addon/dkim-verifier/ or https://github.com/lieser/dkim_verifier/releases.

Bug report
----------
Please report bugs at https://github.com/lieser/dkim_verifier/issues (preferred) or http://forums.mozillazine.org/viewtopic.php?f=48&t=2704121.
To see errors and debug info in the Error Console, enable debug mode in options.

Included third-party Libraries
------------------------------
 - Tom Wu's jsbn library - BigInteger and RSA (http://www-cs-students.stanford.edu/~tjw/jsbn/)
  - jsbn.js - basic BigInteger class
  - jsbn2.js - BigInteger class extension
  - rsa.js - RSAKey class for RSA public key encryption
  - base64.js - String encoder for Base64 and Hex
 - Kenji Urushima's 'RSA-Sign JavaScript Library' (http://kjur.github.com/jsrsasign)
  - asn1hex.js - simple ASN.1 parser to read hexadecimal encoded ASN.1 DER
  - rsasign-1.2.js - RSAKey class extension for RSA signing and verification
 - Joshua Tauberer's DNS Libary (part of Thunderbird Sender Verification Extension) (https://github.com/tauberer/thunderbird-spf)
  - dns.js - DNS Library