/*
 * helper.jsm
 *
 * Version: 1.0.0pre1 (26 October 2013)
 * 
 * Copyright (c) 2013 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* global Components, FileUtils, NetUtil, Promise, Services, CommonUtils */
/* global ModuleGetter, Logging */
/* exported EXPORTED_SYMBOLS, exceptionToStr, readStringFrom, stringEndsWith, tryGetString, tryGetFormattedString, writeStringToTmpFile, DKIM_SigError, DKIM_InternalError */

var EXPORTED_SYMBOLS = [
	"dkimStrings",
	"exceptionToStr",
	"readStringFrom",
	"stringEndsWith",
	"tryGetString",
	"tryGetFormattedString",
	"writeStringToTmpFile",
	"DKIM_SigError",
	"DKIM_InternalError"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/ModuleGetter.jsm");
ModuleGetter.getCommonUtils(this);
ModuleGetter.getPromise(this);

Cu.import("resource://dkim_verifier/logging.jsm");


var log = Logging.getLogger("Helper");

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

	return dkimStrings.stringbundle.GetStringFromName(key, strArray, strArray.length);
};


/**
 * @param {Error} exception
 * 
 * @return {String} formatted error message
 */
function exceptionToStr(exception) {
	"use strict";

	log.trace("exceptionToStr begin");
	
	var str = CommonUtils.exceptionStr(exception);
	log.trace(str);
	
	// cut stack trace from Sqlite.jsm, promise.js, Promise.jsm, Task.jsm calls
	var posStackTrace = str.lastIndexOf("Stack trace: ");
	if (posStackTrace !== -1) {
		var tmp = str.substr(posStackTrace+13);
		tmp = tmp.replace(
			/ < (?:[^ ]| (?!< ))*(?:Sqlite\.jsm|promise\.js|Promise\.jsm|Task\.jsm)(?:[^ ]| (?!< ))*/g,
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
 * 
 * @param {String} str
 * @param {String} strEnd
 * 
 * @return {Boolean}
 */
function stringEndsWith(str, x) {
	"use strict";

	var index = str.lastIndexOf(x);
	return index >= 0 && index === str.length - x.length;
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
		log.error(exceptionToStr(ex));
		return null;
	}
}
/**
 * try to get formatted string from stringbundle
 * 
 * @param stringbundle
 * @param {String} name
 * @param {String[]} params
 * 
 * @return {String|null}
 */
function tryGetFormattedString(stringbundle, name, params) {
	"use strict";

	if (!name) {
		return null;
	}

	try {
		return stringbundle.getFormattedString(name, params);
	} catch (ex) {
		log.error(exceptionToStr(ex));
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
 * 
 * @return {DKIM_SigError}
 */
function DKIM_SigError(errorType) {
	"use strict";

	this.name = dkimStrings.getString("DKIM_SIGERROR");
	this.errorType = errorType;
	this.message = tryGetString(dkimStrings, errorType) ||
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
