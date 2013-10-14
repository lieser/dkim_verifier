/*
 * dkimPolicy.jsm
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 *
 * version: 1.0.0pre1 (13 October 2013)
 *
 * Copyright (c) 2013 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* global Components, Sqlite, Task, CommonUtils, Logging */
/* exported EXPORTED_SYMBOLS, dkimPolicy */

var EXPORTED_SYMBOLS = [
	"dkimPolicy"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
// Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/Sqlite.jsm");
Cu.import("resource://gre/modules/Task.jsm");
Cu.import("resource://services-common/utils.js");

Cu.import("resource://dkim_verifier/logging.jsm");


var dkimPolicyDBConn;
var log = Logging.getLogger("dkimPolicy");

var dkimPolicy = {
	/**
	 * 
	 * @param {String} fromAddress
	 * 
	 * @return 
	 */
	shouldBeSigned: function (fromAddress) {
		// let file = FileUtils.getFile("ProfD", ["my_db_file_name.sqlite"]);
		// let mDBConn = Services.storage.openDatabase(file); // Will also create the file if it does not exist
		// mDBConn.close();
		}
};



function init() {
	log.fatal("fatal");
	log.error("error");
	log.warn("warn");
	log.info("info");
	log.config("config");
	log.debug("debug");
	log.trace("trace");
	log.trace("init");

	Task.spawn(function () {
		dkimPolicyDBConn = yield Sqlite.openConnection({path: "dkimPolicy.sqlite"});
		log.trace("connectet");

		var tableExists = yield dkimPolicyDBConn.tableExists("test");
		if (!tableExists) {
			log.trace("tableExists == false");
			dkimPolicyDBConn.execute("CREATE TABLE test (foo INTEGER, bar STRING)");
			log.trace("createtable");
		}
		log.trace("tableExists == true");

	}).then(function (result) {
		// result == "Resolution result for the task: Value!!!"
		// The result is undefined if no special Task.Result exception was thrown.

		log.debug("result: "+result);
		log.trace("end");
	}, function (exception) {
		// Failure!  We can inspect or report the exception.
		log.fatal(CommonUtils.exceptionStr(exception));

	});
}

function shutdown() {
	log.trace("shutdown");

	// close connection
	if (dkimPolicyDBConn) {
		dkimPolicyDBConn.close();
	}
}

init();
