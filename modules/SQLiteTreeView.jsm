/*
 * SQLiteTreeView.jsm
 * 
 * Implements a nsITreeView for a SQLite DB table.
 *
 * Version: 1.1.0pre1 (19 November 2017)
 * 
 * Copyright (c) 2013-2017 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* eslint strict: ["warn", "function"] */
/* global Components, OS, FileUtils, Services */
/* exported EXPORTED_SYMBOLS, SQLiteTreeView */

var EXPORTED_SYMBOLS = [
	"SQLiteTreeView"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/osfile.jsm");
Cu.import("resource://gre/modules/Services.jsm");


/**
 * SQLiteTreeView
 * Implements nsITreeView and some additional methods.
 * 
 * based on http://www.simon-cozens.org/content/xul-mozstorage-and-sqlite
 * 
 * @constructor
 * 
 * @param {String} dbPath The database file to open. This can be an absolute or relative path. If a relative path is given, it is interpreted as relative to the current profile's directory.
 * @param {String} tableName Table to be displayed
 * @param {String[]} columns Columns to be displayed in the same order as in the tree
 */
function SQLiteTreeView(dbPath, tableName, columns) {
	"use strict";

	// Retains absolute paths and normalizes relative as relative to profile.
	var path = OS.Path.join(OS.Constants.Path.profileDir, dbPath);
	this.file = FileUtils.File(path);
	
	// test that db exists
	if (!this.file.exists()) {
		throw new Error("SQLite File "+path+" must exist");
	}
	
	this.tableName = tableName.replace(/\W/g, "");
	this.columns = columns.map(function (elem) {
		return elem.replace(/\W/g, "");
	});
	this.columnClause = this.columns.join(", ");
	this.insertParamsClause = ":"+this.columns.join(", :");
}
SQLiteTreeView.prototype = {
	/*
	 * internal methods
	 */
	
	/**
	 * Updates orderClause. Should be called if the sort order is changed
	 * @return {void}
	 */
	_updateOrderClause: function SQLiteTreeView__updateOrderClause() {
		"use strict";

		this.orderClause = this.sortOrder.map(function (elem) {
			return this.columns[elem.index] + (elem.orderDirection ? " DESC": "");
		}, this).join(", ");
		// dump(this.orderClause+"\n");
	},
		
	/**
	 * Executes sql an returns the result
	 * 
	 * @param {String} sql
	 * @param {Object} params named params
	 * 
	 * @return {String[][]}
	 */
	_doSQL: function SQLiteTreeView__doSQL(sql, params) {
		"use strict";

		var rv = [];
		var statement;
		try {
			statement = this.conn.createStatement(sql);
			// Named params.
			if (params && typeof(params) == "object") {
				for (let k in params) {
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
			if (statement) {
				statement.finalize();
			}
		}
		return rv;
	},

	/**
	 * Get the rowid of the rows
	 * 
	 * @param {Number[]} rows
	 * 
	 * @return {Number[]} rowids
	 */
	_getRowids: function SQLiteTreeView__getRowids(rows) {
		"use strict";

		var rowids = [];
		for (var i = 0; i < rows.length; i++) {
			rowids.push(this._doSQL(
				"SELECT rowid, "+this.columnClause+" FROM "+this.tableName+"\n" +
				"ORDER BY "+this.orderClause+"\n" +
				"LIMIT 1 OFFSET "+rows[i]+";"
			)[0][0]);
		}
		return rowids;
	},
	
	/*
	 * SQLiteTreeView methods
	 */

	/**
	 * Adds a new row to the database
	 * 
	 * @param {Object} params Named params to insert
	 * @return {void}
	 */
	addRow: function SQLiteTreeView_addRow(params) {
		"use strict";

		// add row
		this._doSQL(
			"INSERT INTO "+this.tableName+" ("+this.columnClause+")\n" +
			"VALUES ("+this.insertParamsClause+");",
			params
		);
		
		// update tree
		this.treebox.rowCountChanged(0, 1);
		this.treebox.invalidate();
	},
	
	/**
	 * Delete selected rows
	 * @return {void}
	 */
	deleteSelectedRows: function SQLiteTreeView_deleteSelectedRows() {
		"use strict";

		// get selected rows
		var selectedRows = [];
		var start = {};
		var end ={};
		var numRanges = this.selection.getRangeCount();

		for (var t = 0; t < numRanges; t++) {
			this.selection.getRangeAt(t,start,end);
			for (var v = start.value; v <= end.value; v++) {
				selectedRows.push(v);
			}
			// this.treebox.rowCountChanged(start, start-end);
		}

		// get rowids
		var rowids = this._getRowids(selectedRows);
		// delete rows
		for (var i = 0; i < selectedRows.length; i++) {
			this._doSQL(
				"DELETE FROM "+this.tableName+"\n" +
				"WHERE rowid = :rowid;",
				{rowid: rowids[i]}
			);
		}
		// update tree
		this.treebox.rowCountChanged(0, -rowids.length);
		this.treebox.invalidate();
	},
	
	/*
	 * nsITreeView attributes/methods
	 */
	
	get rowCount() {
		"use strict";

		return this._doSQL("SELECT count(*) FROM "+this.tableName)[0][0];
	},
	
	// cycleCell
	
	cycleHeader: function SQLiteTreeView_cycleHeader(col) {
		"use strict";

		if (col.index === this.sortOrder[0].index) {
			// change sort order direction
			this.sortOrder[0].orderDirection = !this.sortOrder[0].orderDirection ;
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
		"use strict";

		var res = this._doSQL(
			"SELECT "+this.columnClause+" FROM "+this.tableName+"\n" +
			"ORDER BY "+this.orderClause+"\n" +
			"LIMIT 1 OFFSET "+row+";"
		);
		return res[0][column.index];
	},
	
	// getCellValue
	
	getColumnProperties: function SQLiteTreeView_getColumnProperties(/*colid,col,props*/) {},
	getImageSrc: function SQLiteTreeView_getImageSrc(/*row,col*/){
		"use strict";

		return null;
	},
	getLevel: function SQLiteTreeView_getLevel(/*row*/){
		"use strict";

		return 0;
	},
	getRowProperties: function SQLiteTreeView_getRowProperties(/*row,props*/){},
	isContainer: function SQLiteTreeView_isContainer(/*row*/){
		"use strict";

		return false;
	},
	
	isEditable: function SQLiteTreeView_isEditable(row, col) {
		"use strict";

		return col.editable;
	},
	
	isSeparator: function SQLiteTreeView_isSeparator(/*row*/){
		"use strict";

		return false;
	},
	isSorted: function SQLiteTreeView_isSorted(){
		"use strict";

		return true;
	},
	
	setCellText: function SQLiteTreeView_setCellText(row, col, value) {
		"use strict";

		var rowid = this._getRowids([row])[0];
		this._doSQL(
			"UPDATE "+this.tableName+"\n" +
			"SET "+this.columns[col.index]+" = :value\n" +
			"WHERE rowid = :rowid;",
			{"value":value, "rowid":rowid}
		);
	},
	
	// setCellValue
	
	setTree: function SQLiteTreeView_setTree(treebox) {
		"use strict";

		this.treebox = treebox;
		
		if (treebox) {
			// open connection
			this.conn = Services.storage.openDatabase(this.file);
			
			// test that table exists
			if (!this.conn.tableExists(this.tableName)) {
				throw new Error("Table "+this.tableName+" must exist");
			}
	
			// init sort order
			this.sortOrder = [];
			for (var i=0; i<treebox.columns.count; i++) {
				this.sortOrder.push({"index":i, "orderDirection ": 0});
			}
			this._updateOrderClause();
		} else {
			if (this.conn && this.connectionReady) {
				// close connection
				this.conn.close();
				// this.conn = null;
			}
		}
	},
};
