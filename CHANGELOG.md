# Changelog

<!-- markdownlint-configure-file {"no-duplicate-heading": { "siblings_only": true } } -->

All notable changes to this project will be documented in this file.

## Unreleased

### Other

- Added Russian translation.

## 6.2.0 (2025-09-18)

### Enhancements

- Authentication-Results header: Sort DKIM, SPF and DMARC results from ARH, even when not replacing the add-ons verification (#534).
- Authentication-Results header: All results are now accepted if reading of non RFC compliant ARHs is enabled (#547).
  This improves support for invalid headers by Outlook.
- Detect outgoing messages in Locals Folder (#114).
- Provide preview of the colors for the From header highlighting (#439).

### Fixes

- Libunbound resolver: Make unloading of libraries more robust in case the wrong one got loaded.
- Fix alignment of warning symbol on MacOS (#531).

### Other

- Updated default rules and favicons.

## 6.1.0 (2025-06-01)

### Enhancements

- Added an option to display the DKIM header when an e-mail with a DKIM signature, SPF or DMARC result is viewed (#462).
- Authentication-Results header: Invalid headers by Outlook are now accepted if reading of non RFC compliant ARHs is enabled (#423).
- The DKIM selector is now displayed in the DKIM button pop-up (#510).
- The options page of the add-on can now be opened from the DKIM button pop-up.

### Fixes

- Fixed parsing of a From header that contains MIME encoded non-ASCII characters when reading a saved result (#529).

### Other

- Updated default rules and favicons.

## 6.0.1 (2025-03-10)

### Fixes

- Fixed the JavaScript DNS library resolver (#501).

## 6.0.0 (2025-03-09)

### Breaking Changes

- Now requires at least Thunderbird 128.
- Remove migration of options from versions before 4.0.0.

### Enhancements

- Fixed incompatibility with Thunderbird 136 (#494).
- Authentication-Results header: Improve default behavior about which headers are trusted.
  Instead of trusting all it now depends on the newest ARH (#465).

### Fixes

- If the DKIM result fails because of the check of the sign rules the detailed view now still shows the details of the DKIM signature (#495).
- Authentication-Results header: If only an AUID is included again heuristically extract the SDID from it.
- Fixed setting default values for boolean preferences with policies on macOS via a `.plist` (#499).

### Other

- Updated default rules and favicons (#497).

## 5.6.0 (2025-02-17)

### Enhancements

- Support setting default values for preferences with managed storage (#268).
- An explicit alignment between the AUID and the From address is no longer enforced.
- Authentication-Results header: If replacing the add-ons verification, the SDID alignment is checked against the From address (#452).
- Authentication-Results header: If replacing the add-ons verification, the signature and hash algorithm are now shown in the details view.

### Fixes

- Encoding errors in the RSA/Ed25519 key or signature now result in an invalid DKIM signature instead of an internal error.

## 5.5.0 (2025-01-11)

### Enhancements

- Show all DKIM signatures with additional details in the DKIM button pop-up (#160, #299).
- Improved table views for sign rules and DKIM keys (#248, #305).
  E.g. it is now possible to delete multiple entries at once.
- Allow multiple `*` globs in the From pattern of sign rules (#471, #472).
- Changed the default color scheme for highlighting of the From header to better work with dark mode (#460).
- Changed the header icon to now have the same colors as Thunderbirds own icons.

### Fixes

- Fixed potential parsing error when extracting the received time from the last Received header (#455).
- When parsing now support comments inside comments up to a recursion of 3 (#466).

### Other

- Added Vietnamese translation (by vtvinh24) (#485).
- Updated default rules and favicons (#440, #443, #444, #447, #457, #461).
- Updated Brazilian Portuguese translations (#450).
- Updated French translations (#459).

## 5.4.0 (2023-11-16)

### Enhancements

- Added support for using the Brand Indicators for Message Identification (BIMI)
  when showing favicons is enabled (#242).
- Added the possibility to show a favicon for a specific From address or AUID (#107).
- Don't save DKIM results that contain a temporary error.
- Show proper error message if parsing of a message failed.
- Show DKIM label if "Hide labels column" is enabled.
- Authentication-Results header: if reading of non RFC compliant ARHs is enabled,
  a `:` in a property value is now allowed without the value being in a quoted-string.
- Authentication-Results header: don't restrict result keyword for unknown methods.

### Fixes

- Fixed signature verification if a signed header contains a non ASCII character.
- Fixed support for Thunderbird Conversations add-on in Thunderbird 115 and later (#395).
- Libunbound resolver: Fixed using a relative path to the profile directory in Thunderbird 115 and later (#385).

### Other

- Added Polish translation (by dMbski) (#392).
- Options navigation is now flat.
- Updated default rules and favicons (#387, #393, #399).

## 5.3.1 (2023-06-08)

### Fixes

- Fixed incompatibility with Thunderbird 115 if no preferences exist, e.g. a new installation.

## 5.3.0 (2023-06-06)

### Enhancements

- Fixed incompatibility with Thunderbird 115 (#364).
- Support the offline mode of Thunderbird.
  No DNS queries are done if Thunderbird is in the offline mode (#129).
- JSDNS: Support IPv6 addresses (#363)
- JSDNS: Improved how the addon behaves if all DNS servers were not reachable.
  By default the addon will now try them again instead of getting in a state there all further DNS queries will fail (#269).
  If getting DNS servers from OS configuration is enabled, they will now also be read from the OS again (#90).

### Other

- Updated default rules and favicons (#365).

## 5.2.0 (2023-04-02)

### Enhancements

- Extract the received time from the last Received header and use it as the verification time (#336).
- Fixed incompatibility with Thunderbird 113 (#352).

### Fixes

- Fixed extension not working for attached or external messages (#216).
  Requires Thunderbird 106 or later.
- Fixed empty tags being treated as ill-formed. This e.g. fixes revoked DKIM keys.
- Fixed tooltip for From header in Thunderbird 102 or newer (#311).
- Fixed missing body resulting in internal error (#347).

### Other

- Added Traditional Chinese translation (by NightFeather) (#335).
- Updated default rules and favicons (#334, #337).

## 5.1.1 (2022-08-15)

### Fixes

- Invalid Reply-To header is now ignored instead of resulting in internal error (#321).

### Other

- Updated default rules and favicons (#323, #326, #327).

## 5.1.0 (2022-07-17)

### Enhancements

- Added heuristic to detect maliciously added unsigned headers (#102).
- Configurable option to warn about unsigned headers that are recommended to be signed (#102, #277).
- Improved theming of header icon in Thunderbird 102.
- Authentication-Results header: Prefer to show failure results that include a reason and are related to the sending domain (#247).

### Fixes

- Fixed error when opening messages in a new window in Thunderbird 102.

### Other

- updated default rules and favicons

## 5.0.0 (2022-06-12)

### Breaking Changes

- now requires at least Thunderbird 91

### Enhancements

- fixed incompatibility with Thunderbird 102 (#306, #312)
- Added support for signing algorithm Ed25519-SHA256 (RFC 8463) (#142)
- JSDNS: fixed incompatibility with Thunderbird 101 (#303)
- Authentication-Results header: check sign algorithm used for DKIM (RFC 8601) (#219)

### Fixes

- fixed multiple from addresses being treated as ill-formed (#304)

### Other

- updated default rules and favicons

## 4.1.1 (2022-02-22)

- fixed blank line in header if email does not contain DKIM signature (Thunderbird 97) (#293)
- fixed some dialog windows being to small (#296)
- fixed header spanning multiple lines possibly being cropped at the bottom
- fixed wrapping of header in Thunderbird 99
- added Ukrainian translation (by lexxai) (#297)

## 4.1.0 (2022-02-06)

- fixed incompatibility with Thunderbird 96 (#279)
- Re-added support for Thunderbird Conversations add-on (#203)
- show proper error message on ill-formed from (#238)
- ignore ill-formed List-Id (#262) and fix parsing of List-Id
- Authentication-Results header: fixed sorting of DKIM results in regards to list id
- fixed options styling for Thunderbird 91
- added Brazilian Portuguese translation (by David BrazSan) (#283)
- Add ability to export/import sign rules (#220)
- Fix layout issues in table views (Sign rules / stored keys) (#248)
- updated default rules and favicons (#263, #266, #274, #281, #284)

## 4.0.0 (2021-04-18)

- now requires at least Thunderbird 78
- fixed incompatibility with Thunderbird 78 (#199)
- removed option to show DKIM result in the statusbarpanel
- Authentication-Results header: fixed parsing of version
- Authentication-Results header: fixed parsing of quoted SDID and AUID (#229, #234)
- Authentication-Results header: fixed missing reason on fail resulting in error (#232)
- libunbound resolver: Don't provide a default path (#199)
- libunbound resolver: Improve options description (#199)
- added about page in options
- added incomplete Swedish translation (by Phoenix)
- added Spanish translation (by Peter O Brien) (#239)
- updated default rules and favicons (#208, #209, #210)

## 3.1.0 (2020-01-22)

- includes changes from 2.2.0
- fix default rules and favicons (#197)

## 2.2.0 (2020-01-19)

- Authentication-Results header: fix relaxed parsing option and trailing ";"
- exposed option on how to treat weak keys. Default is now ignore (was warning since 2.1.0) (#174)
- fixed default text color for unsigned e-mail in dark theme if highlighting of From header is enabled (#181)
- libunbound resolver: add ability to explicitly load dependencies of libunbound (#170, #179)
- updated default rules and favicons (#165, #168, #169, #180)

## 3.0.1 (2019-09-22)

- fixed incompatibility with Thunderbird 70 (#167)
- fixed DKIM status not visible when a message is opened in a new window (#172)
- fixed incompatibility with CompactHeader add-on (#177)
- JSDNS: fixed proxy support (#173)

## 3.0.0 (2019-09-01)

- now requires at least Thunderbird 68
- fixed incompatibility with Thunderbird 68/69 (#115)
- libunbound resolver: remove old root trust anchor (key tag 19036)

## 2.1.0 (2019-08-29)

- Cryptographic Algorithm and Key Usage Update (RFC 8301, #141)
- updated default rules and favicons (#140, #145, #152, #157, #159)
- added Hungarian translation (by Óvári) (#164)

## 2.0.1 (2019-01-18)

- fixed signature verification in case the RSA key has an odd key length (#112)
- fixed DMARC heuristic (#125)
- fixed "*" not being recognized as valid Service Type in DKIM Keys (#134)
- changed update DKIM key button to now update the keys of all DKIM signatures in the e-mail
- Authentication-Results header: fixed mixed case results specified by older SPF specs resulting in a parsing error (#135)
- JSDNS: fixed a problem getting the default DNS servers on Windows (#116, #120)
- JSDNS: reduced default DNS server timeout from 10 to 5 seconds
- updated included third-party libraries
- updated default rules and favicons

## 2.0.0 (2018-04-19)

- now requires at least Thunderbird 52
- added toolbar button and menuitem for sign rules
- added option to try to read non RFC compliant Authentication-Results header
- fixed incompatibility with Thunderbird 57/59/60
- fixed favicons not being shown if the CardBook add-on is installed
- fixed "Add must be signed exception" button being disabled if wrong signer is only a warning
- updated default rules and favicons

## 1.7.0 (2017-07-22)

- libunbound resolver: added ability to specify multiple trust anchors
- libunbound resolver: added new root trust anchor (key tag 20326)
- updated default rules and favicons

## 1.6.5 (2017-05-14)

- added Japanese translation (by SAKURAI Kenichi)
- updated default rules

## 1.6.4 (2017-02-09)

- fixed saving of result with DNSSEC lock enabled
- fixed incompatibility with Thunderbird 52 and libunbound
- updated default rules and favicons

## 1.6.3 (2016-11-20)

- fixed incompatibility with Thunderbird 52
- updated default rules and favicons

## 1.6.2 (2016-10-24)

- fixed incompatibility with Silvermel/Charamel
- fixed Problem with copied header fields
- updated default rules and favicons

## 1.6.1 (2016-09-26)

- fixed problem with old Thunderbird versions and sign rules

## 1.6.0 (2016-09-25)

- added option to indicate successful DNSSEC validation with a lock (enabled by default)
- added option to show the favicon of some known signing domains (enabled by default)
- added option to show the ARH result alongside the add-ons, instead of replacing it
- JSDNS: differentiate between a server error and an non existing DKIM key
- sign rules: ignore must be signed for outgoing messages
- sign rules: updated default rules
- fixed updating a DKIM key or marking it as secure via the "Other Actions" button

## 1.5.1 (2016-06-11)

- fixed verification for external messages
- sign rules: updated default rules

## 1.5.0 (2016-05-17)

- added option to enable/disable DKIM verification for each account
- JavaScript DNS library: added support to use a proxy
- sign rules: updated default rules (added firefox.com)
- DKIM key: empty, but existing DNS record is now treated as a missing key instead as an ill-formed one
- fixed installing problem if extensions.getAddons.cache.enabled is set to false (<https://bugzilla.mozilla.org/show_bug.cgi?id=1187725>)

## 1.4.1 (2016-02-13)

- fixed incompatibility with Thunderbird 46
- Authentication-Results header: fixed trusting all authentication servers

## 1.4.0 (2016-02-08)

- simplified shown error reasons and added advanced option for detailed reasons
- Authentication-Results header: reading of the ARH can now be set for each account
- Authentication-Results header: added option to only trust specific authentication servers
- Authentication-Results header: continue verification if there is no DKIM result in the ARH header
- Authentication-Results header: allow also unknown property types to be compliant with RFC 7601
- Authentication-Results header: fixed bug if ARH header exists, but no message authentication was done
- JavaScript DNS library: no longer get the DNS servers from deactivated interfaces under windows
- libunbound resolver: no longer blocks the UI of Thunderbird
- libunbound resolver: changing preferences no longer needs a restart

## 1.3.6 (2015-09-13)

- fixed error in parsing of Authentication-Results header
- added additional debugging calls

## 1.3.5 (2015-07-11)

- fixed bug if a header field body started with a ":"

## 1.3.4 (2015-06-21)

- added compatibility for Thunderbird 40

## 1.3.3 (2015-03-21)

- fixed bug in the sorting of the results of multiple DKIM signatures

## 1.3.2 (2015-02-21)

- updated default sign rules

## 1.3.1 (2014-12-10)

- DNS errors in DMARC heuristic are now ignored (previously this resulted in an internal error)
- fixed error resulting in incompatibility with Thunderbird 36

## 1.3.0 (2014-12-08)

- added option to treat ill-formed selector tag as as error/warning/nothing (default warning; previous behavior was error)
- added support for multiple signatures
- added option to read Authentication-Results header
- added French translation (by Christophe CHAUVET)

- fixed problem with JavaScript DNS Resolver and long DKIM keys, resulting in error "Key couldn't be decoded"
- fixed incompatibility with compact headers add-on

## 1.2.2 (2014-08-16)

- added Chinese (Simplified) translation (by YFdyh000)
- fixed the showing of a wrong error reason in some cases of a bad RSA signature

## 1.2.1 (2014-06-30)

- fixed an issue in formated strings ("%S" was not replaced)

## 1.2.0 (2014-06-25)

- added option for sign rules to allow also subdomains of the SDIDs (enabled by default)
- fixed comparison of domains (was case sensitive)
- updated default sign rules

## 1.1.2 (2014-05-08)

- fixed error if e-mail is from a domain on the public suffix list (like "googlecode.com")
- updated default sign rules

## 1.1.1 (2014-04-10)

- fixed bug in use of libundboud (non existing domain was treated as server error; caused problems with DMARC)

## 1.1.0 (2014-04-07)

- added options for automatically added sign rules
- added option to use DMARC to heuristically determinate if an e-mail should be signed
- fixed sign rules being automatically added even if signRules are disabled
- fixed bug in getting DNS name server from OS under Linux/Mac (last line was not read)

## 1.0.5 (2014-01-14)

- added Italian translation (by Michele Locati)
- statusbarpanel and tooltip are now set to loading on reverify
- DKIM Keys and signers rules window can now be opened at the same time

## 1.0.4 (2013-12-20)

- fixed bug in an error message of the JavaScript DNS library
- added advanced options for the JavaScript DNS library useful in case of bad network connection (not available through GUI)

## 1.0.3 (2013-12-12)

- fixed bug in sign rules if from address contains capital letters
- fixed verification of unsigned e-mails which are marked as should be signed by sign rules

## 1.0.2 (2013-11-22)

- fixed internal error if sign rules are disabled

## 1.0.1 (2013-11-22)

- fixed DKIM_SIGWARNING_FROM_NOT_IN_SDID

## 1.0.0 (2013-11-21)

- added signers rules
- added key storing
- added libunbound as second DNS resolver (supports DNSSEC)
- from tooltip now also works if Thunderbird's status bar is disabled

- fixed some patterns (A-z to A-Za-z, dkim_safe_char, qp_hdr_value)
- fixed pattern for note tag in DKIM key
- fixed bug in DKIM_SIGWARNING_FROM_NOT_IN_AUID
- validate tag list as specified in Section 3.2 of RFC 6376
- now differentiation between missing and ill-formed tags
- added check that hash declared in DKIM-Signature is included in the hashs declared in the key record
- added check that the hash algorithm in the public key is the same as in the header

## 0.6.3 (2013-10-13)

- fixed bug for detection of configured DNS Servers in Windows
   (if more then one DNS server was configured for an adapter)

## 0.6.2 (2013-10-13)

- fixed bug if "other actions" button of CompactHeader add-on toolbar is not included

## 0.6.1 (2013-10-12)

- better detection of configured DNS Servers in Windows

## 0.6.0 (2013-09-26)

- added option for displaying of header, status bar and tooltip for From header
- fixed false detection of DKIM_SIGERROR_DOMAIN_I
- made options height smaller
- fixed error in "simple" body canonicalization algorithm resulting in "Wrong body hash"
- fixed bug for mixed CRLF and LF EOLs in body (resulting in "Wrong body hash")
- fixed error if external message was viewed (but there is still a problem with IMAP attachments)
- fixed bug ("DKIM-Signature" header name was case sensitive)

## 0.5.1 (2013-09-20)

- added option to get DNS Servers from OS

## 0.5.0 (2013-09-10)

- added support of multiple DNS servers
- added optional saving of the result
- DNS Server not reachable no longer treated as a PERMFAIL
- added TEMPFAIL

## 0.4.4 (2013-08-02)

- changed how msgHdrViewOverlay.css is loaded

## 0.4.3 (2013-07-27)

- header highlighting now works with collapsed header from CompactHeader addon
- works now also if e-mail has LF line ending

## 0.4.2 (2013-06-28)

- fixed alignment of warning-icon in mac (by Nils Maier)

## 0.4.1 (2013-06-28)

- DKIM-Signature header field name now in same style as the others (by Nils Maier)
- fixed bug if message needs to be downloaded from IMAP server
- added German translation (by ionum)
- fixed relaxed canonicalization of a body with only empty lines (by ionum)
- small displaying changes in options

## 0.4.0 (2013-06-09)

- warnings are displayed
- added warning for
  - Signature is expired
  - Signature is in the future
  - From is not in SDID
  - From is not in AUID
  - Signature key is small
- added option to treat testmode as warning, not as error
- added options for highlighting of From header
- added option to always show DKIM-Signature header field
- fixed relaxed body canonicalization for non trailing CRLF
- fixed parsing of Message canonicalization if only one algorithm is named
- added partial support of CNAME record type in DNS Library
- fix bug if nonexisting header field is signed
- fixed parsing of AUID

## 0.3.3 (2013-05-31)

- fixed issue with RSS feeds
- added debug info to rsasign-1.2.js

## 0.3.2 (2013-05-30)

- fixed regex pattern for SDID, Selector and local_part

## 0.3.1 (2013-05-30)

- fixed problem with CompactHeader addon

## 0.3.0 (2013-05-29)

- options dialog added
- body length tag was checked before canonicalization
- fixed simple body canonicalization for empty body or no trailing CRLF
- DNS, RSA, ... helper scripts now in DKIM_Verifier namespace

## 0.2.2 (2013-05-22)

- fixed regex pattern for domain_name ("." was not escaped)

## 0.2.1 (2013-05-22)

- query method was parsed wrong
- last header field was parsed wrong
- DNS exception now caught

## 0.2 (2013-05-16)

- check that from header is signed now included
- key record flags are no longer ignored
- Multiple Instances of a header Field are now supported
- encoding issue for body hash fixed

## 0.1 (2013-05-13)

- Initial release
