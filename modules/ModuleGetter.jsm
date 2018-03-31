/*
 * ModuleGetter.jsm
 *
 * Version: 1.0.2 (31 March 2018)
 *
 * Copyright (c) 2013-2018 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */
 
// options for JSHint
/* jshint strict:true, esnext:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Services, XPCOMUtils */
/* exported EXPORTED_SYMBOLS, ModuleGetter */

"use strict";

var EXPORTED_SYMBOLS = [ "ModuleGetter" ];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");


var ModuleGetter = {
	/**
	 * Defines a getter for the CommonUtils (utils.js) module.
	 * 
	 * Gecko 24 and later: "resource://services-common/utils.js"
	 * Otherwise: "resource://dkim_verifier/mozilla/utils.js"
	 * 
	 * @param {Object} aObject The object to define the lazy getter on.
	 * @param {String} [aName="CommonUtils"] The name of the getter to define on aObject for the module.
	 */
	getCommonUtils: function ModuleGetter_getCommonUtils(aObject, aName="CommonUtils"){
		XPCOMUtils.defineLazyGetter(aObject, aName, function () {
			try {
				var temp = {};
				
				if (Services.vc.compare(Services.appinfo.platformVersion, "24.0-1") >= 0 ||
					Services.appinfo.name == "FossaMail")
				{
					Cu.import("resource://services-common/utils.js", temp);
				} else {
					Cu.import("resource://dkim_verifier/mozilla/utils.js", temp);
				}
				
				return temp.CommonUtils;
			} catch (e) {
				Cu.reportError(e);
			}
		});
	},

	/**
	 * Defines a getter for the Log.jsm module.
	 * 
	 * Gecko 27 and later: "resource://gre/modules/Log.jsm"
	 * Gecko 24-26: "resource://services-common/log4moz.js"
	 * Otherwise: "resource://dkim_verifier/mozilla/log4moz.js"
	 * 
	 * @param {Object} aObject The object to define the lazy getter on.
	 * @param {String} [aName="Log"] The name of the getter to define on aObject for the module.
	 */
	getLog: function ModuleGetter_getLog(aObject, aName="Log"){
		XPCOMUtils.defineLazyGetter(aObject, aName, function () {
			try {
				var temp = {};
				
				if (Services.vc.compare(Services.appinfo.platformVersion, "27.0-1") >= 0 ||
					Services.appinfo.name == "FossaMail")
				{
					Cu.import("resource://gre/modules/Log.jsm", temp);
				} else if (Services.vc.compare(Services.appinfo.platformVersion, "24.0-1") >= 0) {
					Cu.import("resource://services-common/log4moz.js", temp);
				} else {
					Cu.import("resource://dkim_verifier/mozilla/log4moz.js", temp);
				}
				
				return temp.Log || temp.Log4Moz;
			} catch (e) {
				Cu.reportError(e);
			}
		});
	},
	
	/**
	 * Defines a getter for the osfile.jsm module.
	 * 
	 * Note for Thunderbird 17:
	 * This already exists in Thunderbird 17, but is not allowed
	 * to be used from the main threat.
	 * So we load the OS.Path part directly.
	 * We also set OS.Constants.Path.profileDir.
	 * OS.File will not work.
	 * 
	 * Gecko 24 and later: "resource://gre/modules/osfile.jsm"
	 * Otherwise: on WINNT: "resource://gre/modules/osfile/ospath_win_back.jsm"
	 *            Otherwise: "resource://gre/modules/osfile/ospath_unix_back.jsm"
	 * 
	 * @param {Object} aObject The object to define the lazy getter on.
	 * @param {String} [aName="OS"] The name of the getter to define on aObject for the module.
	 */
	getosfile: function ModuleGetter_getosfile(aObject, aName="OS"){
		XPCOMUtils.defineLazyGetter(aObject, aName, function () {
			try {
				var temp = {};
				
				if (Services.vc.compare(Services.appinfo.platformVersion, "24.0-1") >= 0 ||
					Services.appinfo.name == "FossaMail")
				{
					Cu.import("resource://gre/modules/osfile.jsm", temp);
				} else {
					if (Services.appinfo.OS === "WINNT") {
						Cu.import("resource://dkim_verifier/mozilla/ospath_win_back.jsm", temp);
					} else {
						Cu.import("resource://dkim_verifier/mozilla/ospath_unix_back.jsm", temp);
					}
					temp.OS.Constants = {};
					temp.OS.Constants.Path = {};
					temp.OS.Constants.Path.profileDir = Services.dirsvc.get("ProfD", Ci.nsIFile).path;
				}
				
				return temp.OS;
			} catch (e) {
				Cu.reportError(e);
			}
		});
	},

	/**
	 * Defines a getter for the Promise.jsm module.
	 * 
	 * Gecko 24 and later: "resource://gre/modules/Promise.jsm"
	 * Otherwise: "resource://gre/modules/commonjs/promise/core.js"
	 * 
	 * @param {Object} aObject The object to define the lazy getter on.
	 * @param {String} [aName="Promise"] The name of the getter to define on aObject for the module.
	 */
	getPromise: function ModuleGetter_getLog(aObject, aName="Promise"){
		XPCOMUtils.defineLazyGetter(aObject, aName, function () {
			try {
				var temp = {};
				
				if (Services.vc.compare(Services.appinfo.platformVersion, "24.0-1") >= 0 ||
					Services.appinfo.name == "FossaMail")
				{
					Cu.import("resource://gre/modules/Promise.jsm", temp);
				} else {
					Cu.import("resource://gre/modules/commonjs/promise/core.js", temp);
				}
				
				return temp.Promise;
			} catch (e) {
				Cu.reportError(e);
			}
		});
	},
	
	/**
	 * Defines a getter for the Sqlite.jsm module.
	 * 
	 * Gecko 20 and later: "resource://gre/modules/Sqlite.jsm"
	 * Otherwise: "resource://dkim_verifier/mozilla/Sqlite.jsm"
	 * 
	 * @param {Object} aObject The object to define the lazy getter on.
	 * @param {String} [aName="Sqlite"] The name of the getter to define on aObject for the module.
	 */
	getSqlite: function ModuleGetter_getSqlite(aObject, aName="Sqlite"){
		XPCOMUtils.defineLazyGetter(aObject, aName, function () {
			try {
				var temp = {};
				
				if (Services.vc.compare(Services.appinfo.platformVersion, "20.0-1") >= 0 ||
					Services.appinfo.name == "FossaMail")
				{
					Cu.import("resource://gre/modules/Sqlite.jsm", temp);
				} else {
					Cu.import("resource://dkim_verifier/mozilla/Sqlite.jsm", temp);
				}
				
				return temp.Sqlite;
			} catch (e) {
				Cu.reportError(e);
			}
		});
	},
};
