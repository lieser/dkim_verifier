// options for JSHint
/* jshint strict:true, moz:true */
/* global Components, FileUtils, NetUtil, CommonUtils, Logging */
/* exported EXPORTED_SYMBOLS, exceptionToStr, stringEndsWith, tryGetString, tryGetFormattedString, writeStringToTmpFile */

var EXPORTED_SYMBOLS = [
	"exceptionToStr",
	"stringEndsWith",
	"tryGetString",
	"tryGetFormattedString",
	"writeStringToTmpFile"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://services-common/utils.js");

Cu.import("resource://dkim_verifier/logging.jsm");


var log = Logging.getLogger("Helper");

/**
 * @param {Error} exception
 * 
 * @return {String} formatted error message
 */
function exceptionToStr(exception) {
	"use strict";

	log.trace("exceptionToStr begin");
	
	// cut stack from Sqlite.jsm, promise.js, Promise.jsm, Task.jsm calls
	if (exception.stack) {
		var posStackEnd = exception.stack.match(
			/(?:\n[^\n]*(?:Sqlite\.jsm|promise\.js|Promise\.jsm|Task.jsm)[^\n]*)*\n$/
		).index;
		exception.stack = exception.stack.substr(0, posStackEnd+1);
	}
	
	var str = CommonUtils.exceptionStr(exception);
	
	// Sqlite.jsm errors
	if (exception.errors) {
		// exception.errors is an array of mozIStorageError
		str += "\n"+[(e.message) for (e of exception.errors)].join("\n");
		str += "\nreported at: ";
		str += new Error().stack.split("\n")[1];
	}
	
	// DKIM_SigError or DKIM_InternalError errors
	// if (exception instanceof DKIM_SigError ||
	    // exception instanceof DKIM_InternalError) {
		if (exception.errorType) {
			str = exception.errorType+": "+str;
		}
	// }

	log.trace("exceptionToStr end");
	return str;
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
			return;
		}

		// Data has been written to the file.
		log.debug("DKIM: wrote file to "+file.path);
	});
}
