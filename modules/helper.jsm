/*
 * helper.jsm
 *
 * Version: 1.3.1 (10 December 2014)
 * 
 * Copyright (c) 2013-2014 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true, smarttabs:true */
/* global Components, FileUtils, NetUtil, Promise, Services, CommonUtils */
/* global ModuleGetter, Logging */
/* exported EXPORTED_SYMBOLS, addrIsInDomain, domainIsInDomain, exceptionToStr, getBaseDomainFromAddr, getDomainFromAddr, readStringFrom, stringEndsWith, stringEqual, tryGetString, tryGetFormattedString, writeStringToTmpFile, DKIM_SigError, DKIM_InternalError */

var EXPORTED_SYMBOLS = [
	"dkimStrings",
	"addrIsInDomain",
	"domainIsInDomain",
	"exceptionToStr",
	"getBaseDomainFromAddr",
	"getDomainFromAddr",
	"readStringFrom",
	"stringEndsWith",
	"stringEqual",
	"tryGetString",
	"tryGetFormattedString",
	"writeStringToTmpFile",
	"DKIM_SigError",
	"DKIM_InternalError"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/ModuleGetter.jsm");
ModuleGetter.getCommonUtils(this);
ModuleGetter.getPromise(this);

Cu.import("resource://dkim_verifier/logging.jsm");


var log = Logging.getLogger("Helper");
var eTLDService = Components.classes["@mozilla.org/network/effective-tld-service;1"]
	.getService(Components.interfaces.nsIEffectiveTLDService);


/**
 * DKIM stringbundle with the same access methods as XUL:stringbundle
 */
var dkimStrings = {};
dkimStrings.stringbundle = Services.strings.createBundle(
	"chrome://dkim_verifier/locale/dkim.properties"
);
dkimStrings.getString = dkimStrings.stringbundle.GetStringFromName;
dkimStrings.getFormattedString = function (key, strArray) {
	"use strict";

	return dkimStrings.stringbundle.formatStringFromName(key, strArray, strArray.length);
};


/**
 * Returns true if e-mail address is from domain or a subdomain of it.
 * 
 * @param {String} addr
 * @param {String} domain
 * 
 * @return {Boolean}
 */
function addrIsInDomain(addr, domain) {
	"use strict";

	return stringEndsWith(addr, "@" + domain) ||
		stringEndsWith(addr, "." + domain);
}

/**
 * Returns true if domain1 is the same or a subdomain of domain2.
 * 
 * @param {String} domain1
 * @param {String} domain2
 * 
 * @return {Boolean}
 */
function domainIsInDomain(domain1, domain2) {
	"use strict";

	return stringEqual(domain1, domain2) ||
		stringEndsWith(domain1, "." + domain2);
}

/**
 * @param {Error} exception
 * 
 * @return {String} formatted error message
 */
function exceptionToStr(exception) {
	"use strict";

	log.trace("exceptionToStr begin");
	
	if(!exception) {
		log.fatal("exceptionToStr: exception undefined or null");
		exception = new Error();
	}

	var str = CommonUtils.exceptionStr(exception);
	log.trace(str);
	
	// cut stack trace from Sqlite.jsm, promise.js, Promise.jsm, Task.jsm calls
	var posStackTrace = str.lastIndexOf("Stack trace: ");
	if (posStackTrace !== -1) {
		var tmp = str.substr(posStackTrace+13);
		tmp = tmp.replace(
			/ < (?:[^ ]| (?!< ))*(?:Sqlite\.jsm|promise\.js|Promise\.jsm|Promise-backend\.js|Task\.jsm)(?:[^ ]| (?!< ))*/g,
			""
		);
		str = str.substr(0, posStackTrace+13) + tmp;
	}
	
	// Sqlite.jsm errors
	if (exception.errors) {
		// exception.errors is an array of mozIStorageError
		str += "\n"+[(e.message) for (e of exception.errors)].join("\n");
		str += "\nreported at: ";
		str += new Error().stack.split("\n")[1];
	}
	
	// DKIM_SigError or DKIM_InternalError errors
	if (exception instanceof DKIM_SigError ||
	    exception instanceof DKIM_InternalError) {
		if (exception.errorType) {
			str = exception.errorType+": "+str;
		}
	}

	log.trace("exceptionToStr end");
	return str;
}

/**
 * Returns the base domain for an e-mail address; that is, the public suffix
 * with a given number of additional domain name parts.
 * 
 * @param {String} addr
 * @param {Number} [aAdditionalParts=0]
 * 
 * @return {String}
 */
function getBaseDomainFromAddr(addr, aAdditionalParts=0) {
	"use strict";

	// var fullDomain = addr.substr(addr.lastIndexOf("@")+1);
	var nsiURI = Services.io.newURI("http://"+addr, null, null);
	var res;
	try {
		res = eTLDService.getBaseDomain(nsiURI, aAdditionalParts);
	} catch (e) {
		// domains like "blogspot.co.uk", "blogspot.com", "googlecode.com"
		// are on the public suffix list, but should be valid base domains
		// because e-mails may be send from them
		if (e.result === Cr.NS_ERROR_INSUFFICIENT_DOMAIN_LEVELS && aAdditionalParts === 0) {
			// add "invalid" subdomain to avoid error
			var host = "invalid."+nsiURI.asciiHost;
			res = eTLDService.getBaseDomainFromHost(host, 0);
			// remove "invalid" sudomain from result
			res = res.substr(8);
		}
	}
	return res;
}

/**
 * Returns the full domain for an e-mail address
 * 
 * @param {String} addr
 * 
 * @return {String}
 */
function getDomainFromAddr(addr) {
	"use strict";

	return addr.substr(addr.lastIndexOf("@")+1);
}

/**
 * Reads from a source asynchronously into a String.
 * 
 * Based on https://developer.mozilla.org/en-US/docs/Code_snippets/File_I_O#Asynchronously
 * 
 * @param {String|nsIURI|nsIFile|nsIChannel|nsIInputStream} aSource The source to read from.
 * 
 * @return {Promise<String>}
 */
function readStringFrom(aSource) {
	"use strict";

	log.trace("readStringFrom begin");

	var defer = Promise.defer();

	NetUtil.asyncFetch(aSource, function(inputStream, status) {
		if (!Components.isSuccessCode(status)) {
			// Handle error!
			defer.reject("readStringFrom: nsresult: "+status);
			// defer.reject(Object.keys(Components.results).find(o=>o[status] === value));
			log.trace("readStringFrom nsresult: "+status);
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
 * @param {String} str
 * @param {String} strEnd
 * 
 * @return {Boolean}
 */
function stringEndsWith(str, x) {
	"use strict";

	var index = str.toLowerCase().lastIndexOf(x.toLowerCase());
	return index >= 0 && index === str.length - x.length;
}

/**
 * Returns true if str1 is equal str2.
 * Comparison is done case insensitive.
 * 
 * @param {String} str1
 * @param {String} str2
 * 
 * @return {Boolean}
 */
function stringEqual(str1, str2) {
	"use strict";

	return str1.toLowerCase() === str2.toLowerCase();
}

/**
 * try to get string from stringbundle
 * 
 * @param stringbundle
 * @param {String} name
 * 
 * @return {String|null}
 */
function tryGetString(stringbundle, name) {
	"use strict";

	if (!name) {
		return null;
	}

	try {
		return stringbundle.getString(name);
	} catch (ex) {
		log.warn(exceptionToStr(ex));
		return null;
	}
}

/**
 * try to get formatted string from stringbundle
 * 
 * @param stringbundle
 * @param {String} name
 * @param {String[]} [params]
 * 
 * @return {String|null}
 */
function tryGetFormattedString(stringbundle, name, params = []) {
	"use strict";

	if (!name) {
		return null;
	}

	try {
		return stringbundle.getFormattedString(name, params);
	} catch (ex) {
		log.warn(exceptionToStr(ex));
		return null;
	}
}

/**
 * Writes a String to a file in the operating system's temporary files directory.
 * 
 * Based on https://developer.mozilla.org/en-US/docs/Code_snippets/File_I_O#Write_a_string
 * 
 * @param {String} string
 * @param {String} fileName
 */
function writeStringToTmpFile(string, fileName) {
	"use strict";
	
	var file = Components.classes["@mozilla.org/file/directory_service;1"]
					.getService(Components.interfaces.nsIProperties)
					.get("TmpD", Components.interfaces.nsIFile);
	file.append(fileName);
	
	// file is nsIFile, data is a string

	// You can also optionally pass a flags parameter here. It defaults to
	// FileUtils.MODE_WRONLY | FileUtils.MODE_CREATE | FileUtils.MODE_TRUNCATE;
	var ostream = FileUtils.openSafeFileOutputStream(file);

	var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].
					createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
	converter.charset = "UTF-8";
	var istream = converter.convertToInputStream(string);

	// The last argument (the callback) is optional.
	NetUtil.asyncCopy(istream, ostream, function(status) {
		if (!Components.isSuccessCode(status)) {
			// Handle error!
			log.debug("writeStringToTmpFile nsresult: "+status);
			return;
		}

		// Data has been written to the file.
		log.debug("DKIM: wrote file to "+file.path);
	});
}

/**
 * DKIM signature error.
 * 
 * @constructor
 * 
 * @param {String} errorType
 * @param {String[]} [errorStrParams]
 * 
 * @return {DKIM_SigError}
 */
function DKIM_SigError(errorType, errorStrParams = []) {
	"use strict";

	this.name = dkimStrings.getString("DKIM_SIGERROR");
	this.errorType = errorType;
	this.errorStrParams = errorStrParams;
	this.message =
		tryGetFormattedString(dkimStrings, errorType, errorStrParams) ||
		errorType ||
		dkimStrings.getString("DKIM_SIGERROR_DEFAULT");

	// modify stack and lineNumber, to show where this object was created,
	// not where Error() was
	var err = new Error();
	this.stack = err.stack.substring(err.stack.indexOf('\n')+1);
	this.lineNumber = parseInt(this.stack.match(/[^:]*$/m), 10);
}
DKIM_SigError.prototype = new Error();
DKIM_SigError.prototype.constructor = DKIM_SigError;

/**
 * DKIM internal error
 * 
 * @constructor
 * 
 * @param {String} message
 * @param {String} [errorType]
 * 
 * @return {DKIM_InternalError}
 */
function DKIM_InternalError(message, errorType) {
	"use strict";

	this.name = dkimStrings.getString("DKIM_INTERNALERROR");
	this.errorType = errorType;
	this.message = message ||
		tryGetString(dkimStrings, errorType) ||
		errorType ||
		dkimStrings.getString("DKIM_INTERNALERROR_DEFAULT");
	
	// modify stack and lineNumber, to show where this object was created,
	// not where Error() was
	var err = new Error();
	this.stack = err.stack.substring(err.stack.indexOf('\n')+1);
	this.lineNumber = parseInt(this.stack.match(/[^:]*$/m), 10);
}
DKIM_InternalError.prototype = new Error();
DKIM_InternalError.prototype.constructor = DKIM_InternalError;
