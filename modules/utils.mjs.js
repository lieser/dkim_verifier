/*
 * utils.mjs.js
 *
 * Version: 3.0.0pre1 (31 January 2020)
 *
 * Copyright (c) 2013-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable no-use-before-define */

const PREF = {
	DNS: {
		RESOLVER: {
			JSDNS: 1,
			LIBUNBOUND: 2,
		}
	},
	ENABLE: {
		DEFAULT: 0,
		TRUE: 1,
		FALSE: 2,
	},
	KEY: {
		STORING: {
			DISABLED: 0,
			STORE: 1,
			COMPARE: 2,
		}
	},
	POLICY: {
		SIGN_RULES: {
			AUTO_ADD_RULE: {
				FOR: {
					FROM: 0,
					SUBDOMAIN: 1,
					BASE_DOMAIN: 2,
				}
			}
		}
	},
	SHOW: {
		NEVER: 0,
		DKIM_VALID: 10,
		DKIM_VALID_ALL: 20,
		DKIM_SIGNED: 30,
		EMAIL: 40,
		MSG: 50,
	},
	STATUSBARPANEL: {
		RESULT: {
			STYLE: {
				TEST: 1,
				ICON: 2,
			}
		}
	}
};

/**
 * Deferred Promise
 * @class
 * @template T
 * @property {Promise<T>} promise
 * @property {Function} resolve
 *           Function to call to resolve promise
 * @property {Function} reject
 *           Function to call to reject promise
 */
class Deferred {
	constructor() {
		this.promise = new Promise((resolve, reject) => {
			this.resolve = resolve;
			this.reject = reject;
		});
	}
}

class Stringbundle {
	/**
	 * DKIM stringbundle with the same access methods as XUL:stringbundle
	 *
	 * @constructor
	 * @param {string} propertiesPath
	 */
	constructor(propertiesPath) {
		this.stringbundle = Services.strings.createBundle(propertiesPath);

		/** @type {nsIStringBundle["GetStringFromName"]} */
		this.getString = this.stringbundle.GetStringFromName;

		/**
		 * @param {string} key
		 * @param {(string|string[])[]} strArray
		 * @return {string}
		 */
		this.getFormattedString = function (key, strArray) {
			return this.stringbundle.formatStringFromName(key, strArray, strArray.length);
		};
	}
}
// var dkimStrings = new Stringbundle("chrome://dkim_verifier/locale/dkim.properties");

/**
 * Returns true if e-mail address is from domain or a subdomain of it.
 *
 * @param {string} addr
 * @param {string} domain
 *
 * @return {boolean}
 */
export function addrIsInDomain(addr, domain) {
	return stringEndsWith(addr, `@${domain}`) ||
		stringEndsWith(addr, `.${domain}`);
}

/**
 * Returns true if e-mail address is from the domain or a subdomain of it or if
 * the domain is a subdomain of the e-mail address.
 *
 * @param {string} addr
 * @param {string} domain
 *
 * @return {boolean}
 */
export function addrIsInDomain2(addr, domain) {
	return stringEndsWith(addr, `@${domain}`) ||
		stringEndsWith(addr, `.${domain}`) ||
		stringEndsWith(domain, `.${getDomainFromAddr(addr)}`);
}

/**
 * Returns true if domain1 is the same or a subdomain of domain2.
 *
 * @param {string} domain1
 * @param {string} domain2
 *
 * @return {boolean}
 */
export function domainIsInDomain(domain1, domain2) {
	return stringEqual(domain1, domain2) ||
		stringEndsWith(domain1, `.${domain2}`);
}

/**
 * Returns the base domain for an e-mail address; that is, the public suffix
 * with a given number of additional domain name parts.
 *
 * @param {string} addr
 * @param {number} [aAdditionalParts=0]
 *
 * @return {string}
 */
function getBaseDomainFromAddr(addr, aAdditionalParts=0) {
	// var fullDomain = addr.substr(addr.lastIndexOf("@")+1);
	var nsiURI = Services.io.newURI(`http://${addr}`, null, null);
	var res;
	try {
		res = eTLDService.getBaseDomain(nsiURI, aAdditionalParts);
	} catch (e) {
		// domains like "blogspot.co.uk", "blogspot.com", "googlecode.com"
		// are on the public suffix list, but should be valid base domains
		// because e-mails may be send from them
		if (e.result === Cr.NS_ERROR_INSUFFICIENT_DOMAIN_LEVELS && aAdditionalParts === 0) {
			// add "invalid" subdomain to avoid error
			let invalidSub = "invalid.";
			var host = invalidSub + nsiURI.asciiHost;
			res = eTLDService.getBaseDomainFromHost(host, 0);
			// remove "invalid" subdomain from result
			res = res.substr(invalidSub.length);
		}
	}
	return res;
}

/**
 * Returns the full domain for an e-mail address
 *
 * @param {string} addr
 *
 * @return {string}
 */
export function getDomainFromAddr(addr) {
	return addr.substr(addr.lastIndexOf("@")+1);
}

/**
 * Reads from a source asynchronously into a String.
 *
 * Based on https://developer.mozilla.org/en-US/docs/Code_snippets/File_I_O#Asynchronously
 *
 * @param {string} aSource The source to read from.
 *
 * @return {Promise<string>}
 */
function readStringFrom(aSource) {
	log.trace("readStringFrom begin");

	/** @type {IDeferred<string>} */
	var defer = new Deferred();

	NetUtil.asyncFetch({
		uri: aSource,
		loadUsingSystemPrincipal: true
	}, function(inputStream, status) {
		if (!Components.isSuccessCode(status)) {
			// Handle error!
			defer.reject(new Error(`readStringFrom: nsresult: ${status}`));
			// defer.reject(Object.keys(Components.results).find(o=>o[status] === value));
			log.trace(`readStringFrom nsresult: ${status}`);
			return;
		}

		// The source data is contained within inputStream.
		// You can read it into a string with
		var data = NetUtil.readInputStreamToString(inputStream, inputStream.available());
		defer.resolve(data);
		log.trace("readStringFrom begin");
	});

	return defer.promise;
}

/**
 * Returns true if str ends with x.
 * Comparison is done case insensitive.
 *
 * @param {string} str
 * @param {string} x
 *
 * @return {boolean}
 */
export function stringEndsWith(str, x) {
	const index = str.toLowerCase().lastIndexOf(x.toLowerCase());
	return index >= 0 && index === str.length - x.length;
}

/**
 * Returns true if str1 is equal str2.
 * Comparison is done case insensitive.
 *
 * @param {string} str1
 * @param {string} str2
 *
 * @return {boolean}
 */
export function stringEqual(str1, str2) {
	return str1.toLowerCase() === str2.toLowerCase();
}

/**
 * Get the type an object as a string.
 *
 * From https://javascriptweblog.wordpress.com/2011/08/08/fixing-the-javascript-typeof-operator/
 *
 * @param {any} obj
 *
 * @return {string}
 */
export function toType(obj) {
	return Object.prototype.toString.call(obj).match(/\s([a-zA-Z]+)/)[1];
}

/**
 * try to get string from stringbundle
 *
 * @param {Stringbundle} stringbundle
 * @param {string|undefined} name
 *
 * @return {string|null}
 */
function tryGetString(stringbundle, name) {
	if (!name) {
		return null;
	}

	try {
		return stringbundle.getString(name);
	} catch (ex) {
		log.warn(ex);
		return null;
	}
}

/**
 * try to get formatted string from stringbundle
 *
 * @param {Stringbundle} stringbundle
 * @param {string} name
 * @param {(string|string[])[]} [params]
 *
 * @return {string|null}
 */
function tryGetFormattedString(stringbundle, name, params = []) {
	if (!name) {
		return null;
	}

	try {
		return stringbundle.getFormattedString(name, params);
	} catch (ex) {
		log.warn(ex);
		return null;
	}
}

/**
 * Writes a String to a file in the operating system's temporary files directory.
 *
 * Based on https://developer.mozilla.org/en-US/docs/Code_snippets/File_I_O#Write_a_string
 *
 * @param {string} string
 * @param {string} fileName
 * @return {void}
 */
function writeStringToTmpFile(string, fileName) {
	var file = Components.classes["@mozilla.org/file/directory_service;1"].
					getService(Components.interfaces.nsIProperties).
					get("TmpD", Components.interfaces.nsIFile);
	file.append(fileName);

	// file is nsIFile, data is a string

	// You can also optionally pass a flags parameter here. It defaults to
	// FileUtils.MODE_WRONLY | FileUtils.MODE_CREATE | FileUtils.MODE_TRUNCATE;
	var oStream = FileUtils.openSafeFileOutputStream(file);

	var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].
					createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
	converter.charset = "UTF-8";
	var iStream = converter.convertToInputStream(string);

	// The last argument (the callback) is optional.
	NetUtil.asyncCopy(iStream, oStream, function(status) {
		if (!Components.isSuccessCode(status)) {
			// Handle error!
			log.debug(`writeStringToTmpFile nsresult: ${status}`);
			return;
		}

		// Data has been written to the file.
		log.debug(`DKIM: wrote file to ${file.path}`);
	});
}
