/*
 * SQLiteTreeView.jsm
 * 
 * Version: 1.0.0pre1 (19 October 2013)
 * 
 * Requires Gecko ???
 * 
 * Copyright (c) 2013 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */
// options for JSHint
/* jshint moz:true */
/* global Components, OS, FileUtils, Services */
/* exported EXPORTED_SYMBOLS, SQLiteTreeView */

var EXPORTED_SYMBOLS = [
	"SQLiteTreeView"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/osfile.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

/**
 * SQLiteTreeView
 * implements nsITreeView
 * 
 * based on http://www.simon-cozens.org/content/xul-mozstorage-and-sqlite
 * 
 * @param {String} dbPath The database file to open. This can be an absolute or relative path. If a relative path is given, it is interpreted as relative to the current profile's directory
 * @param {String} tableName
 * @param {String[]} columns
 */
function SQLiteTreeView(dbPath, tableName, columns) {
	// Retains absolute paths and normalizes relative as relative to profile.
	var path = OS.Path.join(OS.Constants.Path.profileDir, dbPath);
	var file = FileUtils.File(path);
	
	this.conn = Services.storage.openDatabase(file);// TODO: close()
	
	this.tableName = tableName;
	this.columns = columns;
	this.columnClause = columns.join(", ");
}
SQLiteTreeView.prototype = {
	_updateOrderClause: function SQLiteTreeView__updateOrderClause() {
		var that = this;
		this.orderClause = this.sortOrder.map(function (elem) {
			return that.columns[elem.index] + (elem.orderDirection  ? " DESC": "");
		}).join(", ");
		// dump(this.orderClause+"\n");
	},
	
	/**
	 * @param {String} sql
	 * @param {Object} params named params
	 */
	_doSQL: function SQLiteTreeView__doSQL(sql, params) {
		var rv = [];
		try {
		var statement = this.conn.createStatement(sql);
			// Named params.
			if (params && typeof(params) == "object") {
				for (var k in params) {
					statement.bindByName(k, params[k]);
				}
			}

			while (statement.executeStep()) {
				var c;
				var thisArray = [];
				for (c=0; c < statement.numEntries; c++) {
					thisArray.push(statement.getString(c));
				}
				rv.push(thisArray);
			}
		// } catch (error) {
			// dump(error);
			// dump(sql+"\n");
			// dump("Error when executing SQL (" + error.result + "): " + error.message);
			// statement.finalize();
			// throw error;
		} finally {
			statement.finalize();
		}
		return rv;
	},

	get rowCount() {
		return this._doSQL("SELECT count(*) FROM "+this.tableName)[0][0];
	},
	
	// cycleCell
	
	cycleHeader: function SQLiteTreeView_cycleHeader(col) {
		if (col.index === this.sortOrder[0].index) {
			// change sort order direction
			this.sortOrder[0].orderDirection  = !this.sortOrder[0].orderDirection ;
		} else {
			// change sort order sequence
			
			// get the column from sortOrder
			var i;
			for (i=0; i<this.sortOrder.length; i++) {
				if (this.sortOrder[i].index === col.index) {
					break;
				}
			}
			var tmp = this.sortOrder[i];
			
			// delete the column from sortOrder
			this.sortOrder.splice(i, 1);
			
			// add the column at the beginning of sortOrder
			this.sortOrder.splice(0, 0, tmp);
		}
		
		this._updateOrderClause();
		this.treebox.invalidate();
		// this.cacheRowNum = -1; // Invalidate cache		
	},
	
	getCellProperties: function SQLiteTreeView_getCellProperties(/*row,col,props*/) {},
	
	getCellText : function SQLiteTreeView_getCellText(row, column) {
		var res = this._doSQL(
			"SELECT "+this.columnClause+" FROM "+this.tableName+"\n" +
			"ORDER BY "+this.orderClause+"\n" +
			"LIMIT 1 OFFSET "+row+";"
		);
		return res[0][column.index];
	},
	
	// getCellValue
	
	getColumnProperties: function SQLiteTreeView_getColumnProperties(/*colid,col,props*/) {},
	getImageSrc: function SQLiteTreeView_getImageSrc(/*row,col*/){ return null; },
	getLevel: function SQLiteTreeView_getLevel(/*row*/){ return 0; },
	getRowProperties: function SQLiteTreeView_getRowProperties(/*row,props*/){},
	isContainer: function SQLiteTreeView_isContainer(/*row*/){ return false; },
	
	isEditable: function SQLiteTreeView_isEditable(row, col) {
		return col.editable;
	},
	
	isSeparator: function SQLiteTreeView_isSeparator(/*row*/){ return false; },
	// isSorted: function SQLiteTreeView_isSorted(){ return false; },
	isSorted: function SQLiteTreeView_isSorted(){ return true; },
	
	setCellText: function SQLiteTreeView_setCellText(row, col, value) {
		var rowid = this._doSQL(
			"SELECT rowid, "+this.columnClause+" FROM "+this.tableName+"\n" +
			"ORDER BY "+this.orderClause+"\n" +
			"LIMIT 1 OFFSET "+row+";"
		)[0][0];
		this._doSQL(
			"UPDATE "+this.tableName+"\n" +
			"SET "+this.columns[col.index]+" = :value\n" +
			"WHERE rowid = :rowid;",
			{"value":value, "rowid":rowid}
		);
	},
	// setCellValue
	
	setTree: function SQLiteTreeView_setTree(treebox) {
		this.treebox = treebox;
		
		if (treebox) {
			// init sort order
			this.sortOrder = [];
			for (var i=0; i<treebox.columns.count; i++) {
				this.sortOrder.push({"index":i, "orderDirection ": 0});
			}
			this._updateOrderClause();
		}
	},
};
