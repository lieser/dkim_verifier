/*
 * SQLiteTreeView.jsm
 * 
 * Implements a nsITreeView for a SQLite DB table.
 *
 * Version: 1.1.0 (31 March 2018)
 * 
 * Copyright (c) 2013-2018 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
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
 * @typedef {Object} Observable
 * @property {Function} subscribe - subscribe a handler, that takes number of added rows as argument 
 * @property {Function} unsubscribe - unsubscribe a handler
 * @property {Function} notify - notify all observers of changes
 */

/**
 * SQLiteTreeView
 * Implements nsITreeView and some additional methods.
 * 
 * based on http://www.simon-cozens.org/content/xul-mozstorage-and-sqlite
 * @extends {nsITreeView}
 */
class SQLiteTreeView {
	/**
	 * Create a new SQLiteTreeView
	 * @constructor
	 * 
	 * @param {String} dbPath The database file to open. This can be an absolute or relative path. If a relative path is given, it is interpreted as relative to the current profile's directory.
	 * @param {String} tableName Table to be displayed
	 * @param {String[]} columns Columns to be displayed in the same order as in the tree
	 * @param {Observable|undefined} observable Observable
	 */
	constructor(dbPath, tableName, columns, observable = undefined) {
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

		// init sort order
		/** @type {{index: number, orderDesc: boolean}[]} */
		this.sortOrder = [];
		for (var i=0; i<this.columns.length; i++) {
			this.sortOrder.push({"index":i, "orderDesc": false});
		}
		this._updateOrderClause();

		this.observable = observable;
	}

	/*
	 * internal methods
	 */
	
	/**
	 * Updates orderClause. Should be called if the sort order is changed
	 * @return {void}
	 */
	_updateOrderClause() {
		this.orderClause = this.sortOrder.map(function (elem) {
			return this.columns[elem.index] + (elem.orderDesc ? " DESC": "");
		}, this).join(", ");
		// dump(this.orderClause+"\n");
	}
		
	/**
	 * Executes sql an returns the result
	 * 
	 * @param {String} sql
	 * @param {Object} [params] named params
	 * 
	 * @return {(String[])[]}
	 */
	_doSQL(sql, params) {
		var rv = [];
		var statement;
		try {
			if (this.conn) {
				statement = this.conn.createStatement(sql);
			} else {
				throw new Error("SQLiteTreeView not correctly initialised (no open connection). Did you use setTree()?");
			}
			// Named params.
			if (params && typeof params === "object") {
				for (let k in params) {
					if (Object.prototype.hasOwnProperty.call(params, k)) {
						statement.bindByName(k, params[k]);
					}
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
	}

	/**
	 * Get the rowID of the rows
	 * 
	 * @param {Number[]} rows
	 * 
	 * @return {string[]} rowIDs
	 */
	_getRowIDs(rows) {
		var rowIDs = [];
		for (var i = 0; i < rows.length; i++) {
			rowIDs.push(this._doSQL(
				"SELECT rowid, "+this.columnClause+" FROM "+this.tableName+"\n" +
				"ORDER BY "+this.orderClause+"\n" +
				"LIMIT 1 OFFSET "+rows[i]+";"
			)[0][0]);
		}
		return rowIDs;
	}

	/**
	 * If observable is set, notify it.
	 * Otherwise, directly update the tree view
	 * 
	 * @param {Number} [rowCountChanged] Number of rows changed
	 * @return {void}
	 */
	_triggerUpdate(rowCountChanged) {
		if (this.observable) {
			this.observable.notify(rowCountChanged);
		} else {
			this.update(rowCountChanged);
		}
	}

	/*
	 * SQLiteTreeView methods
	 */

	/**
	 * Update the tree view
	 * 
	 * @param {Number} [rowCountChanged] Number of rows changed
	 * @return {void}
	 */
	update(rowCountChanged) {
		if (rowCountChanged) {
			this.treeBox.rowCountChanged(0, rowCountChanged);
		}
		this.treeBox.invalidate();
	}

	/**
	 * Adds a new row to the database
	 * 
	 * @param {Object} params Named params to insert
	 * @return {void}
	 */
	addRow(params) {
		// add row
		this._doSQL(
			"INSERT INTO "+this.tableName+" ("+this.columnClause+")\n" +
			"VALUES ("+this.insertParamsClause+");",
			params
		);
		
		// update tree
		this._triggerUpdate(1);
	}
	
	/**
	 * Delete selected rows
	 * @return {void}
	 */
	deleteSelectedRows() {
		// get selected rows
		var selectedRows = [];
		var start = {value: 0};
		var end ={value: -1};
		var numRanges = this.selection.getRangeCount();

		for (var t = 0; t < numRanges; t++) {
			this.selection.getRangeAt(t,start,end);
			for (var v = start.value; v <= end.value; v++) {
				selectedRows.push(v);
			}
		}

		// get rowIDs
		var rowIDs = this._getRowIDs(selectedRows);
		// delete rows
		for (var i = 0; i < selectedRows.length; i++) {
			this._doSQL(
				"DELETE FROM "+this.tableName+"\n" +
				"WHERE rowid = :rowID;",
				{rowID: rowIDs[i]}
			);
		}
		// update tree
		this._triggerUpdate(-rowIDs.length);
	}
	
	/*
	 * nsITreeView attributes/methods
	 */
	
	get rowCount() {
		return this._doSQL("SELECT count(*) FROM "+this.tableName)[0][0];
	}
	
	// cycleCell
	
	cycleHeader(col) {
		if (col.index === this.sortOrder[0].index) {
			// change sort order direction
			this.sortOrder[0].orderDesc = !this.sortOrder[0].orderDesc ;
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
		this._triggerUpdate();
	}
	
	getCellProperties(/*row,col,props*/) {} // eslint-disable-line strict, no-empty-function
	
	getCellText(row, column) {
		var res = this._doSQL(
			"SELECT "+this.columnClause+" FROM "+this.tableName+"\n" +
			"ORDER BY "+this.orderClause+"\n" +
			"LIMIT 1 OFFSET "+row+";"
		);
		return res[0][column.index];
	}
	
	// getCellValue
	
	getColumnProperties(/*colID,col,props*/) {} // eslint-disable-line strict, no-empty-function

	getImageSrc(/*row,col*/){
		return null;
	}

	getLevel(/*row*/){
		return 0;
	}

	getRowProperties(/*row,props*/){} // eslint-disable-line strict, no-empty-function

	isContainer(/*row*/){
		return false;
	}
	
	isEditable(row, col) {
		return col.editable;
	}
	
	isSeparator(/*row*/){
		return false;
	}

	isSorted(){
		return true;
	}
	
	setCellText(row, col, value) {
		var rowID = this._getRowIDs([row])[0];
		this._doSQL(
			"UPDATE "+this.tableName+"\n" +
			"SET "+this.columns[col.index]+" = :value\n" +
			"WHERE rowid = :rowID;",
			{"value":value, "rowID":rowID}
		);
		this._triggerUpdate();
	}
	
	// setCellValue
	
	setTree(treeBox) {
		this.treeBox = treeBox;
		
		if (treeBox) {
			// open connection
			this.conn = Services.storage.openDatabase(this.file);
			
			// test that table exists
			if (!this.conn.tableExists(this.tableName)) {
				throw new Error("Table "+this.tableName+" must exist");
			}
	
			if ( treeBox.columns.count !== this.columns.length) {
				throw new Error("Number of columns to be displayed must be the same as in the tree");
			}

			if (this.observable) {
				var self = this;
				this.updateHandler = x => self.update(x);
				this.observable.subscribe(this.updateHandler);
			}
		} else {
			if (this.conn && this.conn.connectionReady) {
				// close connection
				this.conn.close();
				// this.conn = null;
			}

			if (this.observable) {
				this.observable.unsubscribe(this.updateHandler);
				this.observable = null;
			}
		}
	}
}
