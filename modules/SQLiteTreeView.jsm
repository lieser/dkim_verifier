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
 * @param {String} dbPath The database file to open. This can be an absolute or relative path. If a relative path is given, it is interpreted as relative to the current profile's directory
 * @param {String} tableName
 * @param {String[]} [columns]
 */
function SQLiteTreeView(dbPath, tableName, columns) {
	// Retains absolute paths and normalizes relative as relative to profile.
	var path = OS.Path.join(OS.Constants.Path.profileDir, dbPath);
	var file = FileUtils.File(path);
	
	this.conn = Services.storage.openDatabase(file);// TODO: close()
	
	this.tableName = tableName;
	if (columns) {
		this.columnClause = columns.join(", ");
	} else {
		this.columnClause = "*";
	}
}
SQLiteTreeView.prototype = {
	_updateOrderClause: function SQLiteTreeView__updateOrderClause() {
		this.orderClause = this.sortOrder.map(function (elem) {
			return (elem.index+1) + (elem.orderDirection  ? "": " DESC");
		}).join(", ");
	},

	get rowCount() {
		var res;
		var statement = this.conn.createStatement("SELECT count(*) FROM "+this.tableName);
		try {
			statement.executeStep();
			res = statement.getString(0);
		} finally {
			statement.finalize();
		}
		return res;
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
	
	getCellText : function SQLiteTreeView_getCellText(row,column) {
		var res;
		var statement = this.conn.createStatement(
			"SELECT "+this.columnClause+" FROM "+this.tableName+"\n" +
			"ORDER BY "+this.orderClause+"\n" +
			"LIMIT 1 OFFSET "+row+";"
		);
		try {
			statement.executeStep();
			res = statement.getString(column.index);
		// } catch (e) {
			// dump(e);
		} finally {
			statement.finalize();
		}
		return res;
	},
	
	// getCellValue
	
	getColumnProperties: function SQLiteTreeView_getColumnProperties(/*colid,col,props*/) {},
	getImageSrc: function SQLiteTreeView_getImageSrc(/*row,col*/){ return null; },
	getLevel: function SQLiteTreeView_getLevel(/*row*/){ return 0; },
	getRowProperties: function SQLiteTreeView_getRowProperties(/*row,props*/){},
	isContainer: function SQLiteTreeView_isContainer(/*row*/){ return false; },
	// isEditable
	isSeparator: function SQLiteTreeView_isSeparator(/*row*/){ return false; },
	// isSorted: function SQLiteTreeView_isSorted(){ return false; },
	isSorted: function SQLiteTreeView_isSorted(){ return true; },
	
	// setCellText
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
