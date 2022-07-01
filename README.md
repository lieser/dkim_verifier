DKIM Verifier
=============

This is an add-on for Mozilla Thunderbird that verifies DKIM signatures according to the RFC 6376.

Usage information can be found in the wiki at <https://github.com/lieser/dkim_verifier/wiki>.

Code structure
--------------

The root of the repository can be directly loaded as a temporary Add-on in Thunderbird.

The following directories and files are included in the packed extension:

- `_locales/`: Localize strings.
  More details in the included [readme](_locales/Readme.md).
  Only `.json` files are included in the packed extension.
- `content/`: The background page and various content pages.
  Also contains some shared modules for working with the DOM.
  Only `.html`, `.css` and `.js` files are included in the packed extension.
- `data/`: Data of the included signers rules and favicons.
- `experiments/`: Experiment APIs. Only `.js`, and `.json` files are included in the packed extension.
- `modules/`: Internal JavaScript modules (ECMAScript Modules (ESM) / ES6 Modules).
  Contains most of the business logic.
  Only `.js` files are included in the packed extension.
- `thirdparty`: Most of the included third-party libraries.
- `CHANGELOG.md`: Changelog of user visible changes.
- `icon.svg` / `icon-white.svg`: Icon of the extension.
- `LICENSE.txt`: Licensing information for the extension.
- `manifest.json`: Manifest file containing basic metadata about the extension.
- `README.md`: This readme.
- `THIRDPARTY_LICENSE.txt`: Licensing information for included third party
software components.

Other directories and files are used only for development. This includes:

- `scripts`: Node.js scripts used during development.
- `test`: Automated tests.
  More details in the included [readme](test/Readme.md).

Included third-party Libraries
------------------------------

- Joshua Tauberer's DNS Library (part of Thunderbird Sender Verification Extension) (<https://github.com/tauberer/thunderbird-spf>)
  - dns.js - DNS Library
- ES6 version of the [tweetnacl-js](https://github.com/dchest/tweetnacl-js) `nacl-fast.js` (<https://github.com/hakanols/tweetnacl-es6>)
