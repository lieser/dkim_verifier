DKIM Verifier
=============

This is an add-on for Mozilla Thunderbird that verifies DKIM signatures according to the RFC 6376.

More Information in the wiki at https://github.com/lieser/dkim_verifier/wiki

Included third-party Libraries
------------------------------
 - Tom Wu's jsbn library - BigInteger and RSA (http://www-cs-students.stanford.edu/~tjw/jsbn/) *Version 1.4*
    - jsbn.js - basic BigInteger class
    - jsbn2.js - BigInteger class extension
    - rsa.js - RSAKey class for RSA public key encryption
    - base64.js - String encoder for Base64 and Hex
 - Kenji Urushima's 'RSA-Sign JavaScript Library' (http://kjur.github.com/jsrsasign) *Version 8.0.12*
    - asn1hex.js - simple ASN.1 parser to read hexadecimal encoded ASN.1 DER
    - rsasign-1.2.js - RSAKey class extension for RSA signing and verification
 - Joshua Tauberer's DNS Libary (part of Thunderbird Sender Verification Extension) (https://github.com/tauberer/thunderbird-spf)
    - dns.js - DNS Library
