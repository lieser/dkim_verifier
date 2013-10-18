// options for JSHint
/* jshint strict:true, moz:true */
/* global Components, FileUtils, NetUtil, CommonUtils, Logging */
/* exported EXPORTED_SYMBOLS, writeStringToTmpFile, exceptionToStr */

var EXPORTED_SYMBOLS = [
	"writeStringToTmpFile",
	"exceptionToStr"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://services-common/utils.js");

Cu.import("resource://dkim_verifier/logging.jsm");


var log = Logging.getLogger("Helper");

/*
 * 
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

/**
 * @param {Error} exception
 * 
 *  @return {String} formatted error message
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
	
	log.trace("exceptionToStr end");
	return str;
}
