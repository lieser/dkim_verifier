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


const RULE_SIGNED = 1;
const RULE_NEUTRAL = 2;

// Promise<boolean>
var initialized;
var log = Logging.getLogger("Policy");

var dkimPolicy = {
	/**
	 * Determinates if e-mail by fromAddress should be signed
	 * 
	 * @param {String} fromAddress
	 * @param {Function} callback
	 * 
	 * @return {Promise<Object Boolean>}
	 *         true if fromAddress should be signed
	 *         .sdid {String} Signing Domain Identifier
	 */
	shouldBeSigned: function (fromAddress, callback) {
		var promise = Task.spawn(function () {
			log.trace("shouldBeSigned begin");
			
			yield initialized;
			var conn = yield Sqlite.openConnection({path: "dkimPolicy.sqlite"});
			
			var sqlRes = yield conn.executeCached(
				"SELECT * FROM signers WHERE" +
				"  lower(:from) GLOB addr AND" +
				"  enabled" +
				"  ORDER BY priority DESC" +
				"  LIMIT 1" +
				";",
				{"from": fromAddress});
			
			var result;
			if (sqlRes.length > 0 &&
					sqlRes[0].getResultByName("ruletype") === RULE_SIGNED) {
				result = new Boolean(true);
				result.sdid = sqlRes[0].getResultByName("sdid");
			} else {
				result = new Boolean(false);
			}
			
			log.debug("result: "+result+"; result.sdid: "+result.sdid);
			throw new Task.Result(result);
		});
		promise.then(function onFulfill(result) {
			// result == "Resolution result for the task: Value!!!"
			// The result is undefined if no special Task.Result exception was thrown.
			log.trace("shouldBeSigned end");
			if (callback) {
				callback(result);
			}
		}).then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(CommonUtils.exceptionStr(exception));
		});
		return promise;
	}
};


/**
 * init DB
 * 
 * @return {Promise<boolean>} initialized
 */
function init() {
	var promise = Task.spawn(function () {
		log.trace("init begin");
		
		var dkimPolicyDBConn = yield Sqlite.openConnection({path: "dkimPolicy.sqlite"});

		try {
			yield dkimPolicyDBConn.execute(
				"CREATE TABLE IF NOT EXISTS signers (" +
				"  addr TEXT NOT NULL," +
				"  sdid TEXT," +
				"  ruletype INTEGER NOT NULL," + // 1 (signed); 2 (neutral)
				"  priority INTEGER NOT NULL," +
				"  enabled INTEGER NOT NULL" + // 0 (false) and 1 (true)
				");");
		} finally {
			yield dkimPolicyDBConn.close();
		}
		
		log.debug("initialized");
		log.trace("init end");
		throw new Task.Result(true);
	});
	promise.then(null, function onReject(exception) {
		// Failure!  We can inspect or report the exception.
		log.fatal(CommonUtils.exceptionStr(exception));
	});
	return promise;
}

initialized = init();
