/*
 * dkimPolicy.jsm
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 *
 * version: 1.0.0pre2 (15 October 2013)
 *
 * Copyright (c) 2013 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint esnext:true */
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


// rule types
const RULE_SIGNED = 1;
const RULE_NEUTRAL = 2;
// default rule priorities
const PRIORITY_AUTOINSERT_RULE_SIGNED = 110;
const PRIORITY_DEFAULT_RULE_SIGNED = 210;
const PRIORITY_DEFAULT_RULE_NEUTRAL = 220;
const PRIORITY_USERINSERT_RULE_SIGNED = 310;
const PRIORITY_USERINSERT_RULE_NEUTRAL = 320;

// Promise<boolean>
var initialized;
var log = Logging.getLogger("Policy");

var dkimPolicy = {
	/**
	 * Determinates if e-mail by fromAddress should be signed
	 * 
	 * @param {String} fromAddress
	 * @param {Function} [callback] function callback(result, callbackData)
	 * @param [callbackData]
	 * 
	 * @return {Promise<Object>}
	 *         .shouldBeSigned true if fromAddress should be signed
	 *         .sdid {String} Signing Domain Identifier
	 *         .foundRule {Boolean} true if enabled rule for fromAddress was found
	 */
	shouldBeSigned: function (fromAddress, callback, callbackData) {
		var promise = Task.spawn(function () {
			log.trace("shouldBeSigned Task begin");
			
			yield initialized;
			var conn = yield Sqlite.openConnection({path: "dkimPolicy.sqlite"});
			
			var sqlRes = yield conn.executeCached(
				"SELECT * FROM signers WHERE" +
				"  lower(:from) GLOB addr AND" +
				"  enabled" +
				"  ORDER BY priority DESC" +
				"  LIMIT 1" +
				";",
				{"from": fromAddress}
			);
			
			var result = {};
			if (sqlRes.length > 0) {
				if (sqlRes[0].getResultByName("ruletype") === RULE_SIGNED) {
					result.shouldBeSigned = true;
					result.sdid = sqlRes[0].getResultByName("sdid");
				} else {
					result.shouldBeSigned = false;
				}
				result.foundRule = true;
			} else {
				result.shouldBeSigned = false;
				result.foundRule = false;
			}
			
			log.debug("result.shouldBeSigned: "+result.shouldBeSigned+"; result.sdid: "+result.sdid+
				"; result.foundRule: "+result.foundRule
			);
			log.trace("shouldBeSigned Task end");
			throw new Task.Result(result);
		});
		if (callback !== undefined) {
			promise.then(function onFulfill(result) {
				// result == "Resolution result for the task: Value!!!"
				// The result is undefined if no special Task.Result exception was thrown.
				if (callback) {
					callback(result, callbackData);
				}
			}).then(null, function onReject(exception) {
				// Failure!  We can inspect or report the exception.
				log.fatal(CommonUtils.exceptionStr(exception));
			});
		}
		return promise;
	},
	
	/**
	 * Adds should be signed rule if no enabled rule for fromAddress is found
	 * 
	 * @param {String} fromAddress
	 * @param {String} sdid
	 * 
	 * @return {Promise<Undefined>}
	 */
	signedBy: function (fromAddress, sdid) {
		var promise = Task.spawn(function () {
			log.trace("signedBy Task begin");
			
			var shouldBeSignedRes = yield dkimPolicy.shouldBeSigned(fromAddress);
			if (!shouldBeSignedRes.foundRule) {
				yield addRule(fromAddress, sdid, RULE_SIGNED, PRIORITY_AUTOINSERT_RULE_SIGNED);
			}
			
			log.trace("signedBy Task end");
		});
		promise.then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(CommonUtils.exceptionStr(exception));
		});
		return promise;
	},
};

/**
 * Adds rule
 * 
 * @param {String} addr
 * @param {String} sdid
 * @param {Number} ruletype
 * @param {Number} priority
 * 
 * @return {Promise<Undefined>}
 */
function addRule(addr, sdid, ruletype, priority) {
		log.trace("addRule begin");
		
		yield initialized;
		var conn = yield Sqlite.openConnection({path: "dkimPolicy.sqlite"});
		
		log.debug("add rule (addr: "+addr+", sdid: "+sdid+
			", ruletype: "+ruletype+", priority: "+priority+
			", enabled: 1)"
		);
		yield conn.executeCached(
			"INSERT INTO signers VALUES (" +
			"  :addr," +
			"  :sdid," +
			"  :ruletype," +
			"  :priority," +
			"  1" + // enabled
			");",
			{
				"addr": addr,
				"sdid": sdid,
				"ruletype": RULE_SIGNED,
				"priority": PRIORITY_AUTOINSERT_RULE_SIGNED,
			}
		);
	
		log.trace("addRule end");
}

/**
 * init DB
 * 
 * @return {Promise<boolean>} initialized
 */
function init() {
	var promise = Task.spawn(function () {
		log.trace("init Task begin");
		
		var dkimPolicyDBConn = yield Sqlite.openConnection({path: "dkimPolicy.sqlite"});

		try {
			yield dkimPolicyDBConn.execute(
				"CREATE TABLE IF NOT EXISTS signers (" +
				"  addr TEXT NOT NULL," +
				"  sdid TEXT," +
				"  ruletype INTEGER NOT NULL," + // 1 (signed); 2 (neutral)
				"  priority INTEGER NOT NULL," +
				"  enabled INTEGER NOT NULL" + // 0 (false) and 1 (true)
				");"
			);
		} finally {
			yield dkimPolicyDBConn.close();
		}
		
		log.debug("initialized");
		log.trace("init Task end");
		throw new Task.Result(true);
	});
	promise.then(null, function onReject(exception) {
		// Failure!  We can inspect or report the exception.
		log.fatal(CommonUtils.exceptionStr(exception));
	});
	return promise;
}

initialized = init();
