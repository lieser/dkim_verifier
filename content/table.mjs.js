/**
 * An editable table for showing data.
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser */

class TableCellEditable extends HTMLTableCellElement {
	constructor() {
		super();

		this._span = document.createElement("span");

		this._input = document.createElement("input");
		this._input.hidden = true;
		this._input.type = "text";
		this._input.size = 1;
		this._input.style.padding = "0px";
		this._input.style.margin = "0px";
		this._input.style.width = "100%";
		this._input.style.borderStyle = "hidden";


		this.appendChild(this._span);
		this.appendChild(this._input);
	}

	static create() {
		/** @type {TableCellEditable} */
		// @ts-expect-error
		const cell = document.createElement("td", { is: "table-cell-editable" });
		return cell;
	}

	/**
	 * @param {Event} event
	 * @returns {TableCellEditable}
	 */
	static getFromEvent(event) {
		if (!(event.target instanceof HTMLElement)) {
			const msg = "Could not get TableCellEditable from event: event does not have a HTMLElement target";
			console.warn(msg, event);
			throw new Error(msg);
		}
		const cell = event.target.closest("td");
		if (!(cell instanceof TableCellEditable)) {
			const msg = "Could not get TableCellEditable from event: closest td is not an TableCellEditable";
			console.warn(msg, event);
			throw new Error(msg);
		}
		return cell;
	}

	/**
	 * Get the row the cell belongs too.
	 *
	 * @returns {HTMLTableRowElement}
	 */
	getRow() {
		const tr = this.closest("tr");
		if (!tr) {
			const msg = "Could not get the row for the cell";
			console.warn(msg, this);
			throw new Error(msg);
		}
		return tr;
	}

	/**
	 * @param {string} value
	 */
	set value(value) {
		if (this._span.hidden) {
			throw new Error("Can not set the value of the cell while editing");
		}
		this._span.innerText = value;
	}

	/**
	 * @returns {string}
	 */
	get value() {
		if (this._span.hidden) {
			return this._input.value;
		}
		return this._span.innerText;
	}

	startEdit() {
		this._input.value = this._span.innerText;
		this._span.hidden = true;
		this._input.hidden = false;
		this._input.focus();
	}

	completeEdit() {
		this._span.innerText = this._input.value;
		this._span.hidden = false;
		this._input.hidden = true;
	}

	cancelEdit() {
		this._input.value = this._span.innerText;
		this._span.hidden = false;
		this._input.hidden = true;
	}
}
customElements.define("table-cell-editable", TableCellEditable, { extends: "td" });

export default class DataTable {
	/**
	 * @callback UpdateCellValueCallback
	 * @param {number} rowId
	 * @param {string} columnName
	 * @param {string|number|boolean} value
	 * @return {Promise<void>}
	 */
	/**
	 * @callback DeleteRowCallback
	 * @param {number} rowId
	 * @return {Promise<void>}
	 */

	/**
	* @param {HTMLTableElement} tableElement
	* @param {boolean} [editable]
	* @param {UpdateCellValueCallback} [updatedCellValueCallback]
	* @param {DeleteRowCallback} [deleteRowCallback]
	*/
	constructor(tableElement, editable = false, updatedCellValueCallback = undefined, deleteRowCallback = undefined) {
		this._tbody = tableElement.getElementsByTagName("tbody")[0];
		this._isEditable = editable;
		this._isEditing = false;
		this._updatedCellValueCallback = updatedCellValueCallback;
		this._deleteRowCallback = deleteRowCallback;

		/** @type {HTMLTableRowElement[]} */
		this._selectedRows = [];

		this._columns = Array.from(tableElement.getElementsByTagName("th")).
			map(th => ({ name: th.dataset.name, type: th.dataset.type ?? "string" }));
	}

	/**
	 * @param {Object.<string, string|number|boolean>[]} data
	 * @param {string[]} [sortOrder]
	 * @returns {void}
	 */
	showData(data, sortOrder) {
		if (sortOrder) {
			data.sort((a,b) => {
				for (const column of sortOrder) {
					if (a[column] < b[column]) {
						return -1;
					}
					if (a[column] > b[column]) {
						return 1;
					}
				}
				return 0;
			});
		}

		const tbody = document.createElement("tbody");
		if (this._isEditable) {
			tbody.onclick = (event) => this._select(event);
			tbody.ondblclick = (event) => this._startEdit(event);
			tbody.addEventListener('focusout', (event) => this._stopEditFocusout(event));
			tbody.onkeydown = (event) => this._stopEditKeydown(event);
		}

		for (const item of data) {
			const tr = document.createElement("tr");
			if (item.id !== undefined) {
				tr.dataset.rowId = item.id.toString();
			}
			for (const column of this._columns) {
				const td = TableCellEditable.create();
				tr.appendChild(td);
				if (column.name === undefined) {
					// ignore columns that do not have data-name
					continue;
				}
				td.dataset.columnName = column.name;
				if (!Object.hasOwnProperty.call(item, column.name)) {
					// don't add anything if the item does not have any value for the column
					continue;
				}
				const value = item[column.name];
				switch (column.type) {
					case "number":
						if (typeof value !== "number") {
							throw new Error(`Unexpected type for '${column.name}'.`);
						}
						td.value = value.toString();
						break;
					case "boolean":
						if (typeof value !== "boolean") {
							throw new Error(`Unexpected type for '${column.name}'.`);
						}
						td.value = value ? "1" : "0";
						break;
					default:
						if (typeof value !== "string") {
							throw new Error(`Unexpected type for '${column.name}'.`);
						}
						td.value = value;
						break;
				}
			}
			tbody.appendChild(tr);
		}

		this._tbody.replaceWith(tbody);
		this._tbody = tbody;
	}

	async deleteSelectedRows() {
		for (const tr of this._selectedRows) {
			tr.remove();
			if (this._deleteRowCallback) {
				const rowId = tr.dataset.rowId;
				if (rowId === undefined) {
					throw new Error("Could not get rowId for deleted row");
				}
				await this._deleteRowCallback(parseInt(rowId, 10));
			}
		}
	}

	/**
	 * @param {Event} event
	 * @returns {void}
	 */
	_select(event) {
		if (this._isEditing) {
			return;
		}
		this._unselect();
		const cell = TableCellEditable.getFromEvent(event);
		const tr = cell.getRow();
		tr.setAttribute("selected", "true");
		this._selectedRows.push(tr);
	}

	/**
	 * @returns {void}
	 */
	_unselect() {
		for (const tr of this._selectedRows) {
			tr.removeAttribute("selected");
		}
		this._selectedRows = [];
	}

	/**
	 * @param {Event} event
	 * @returns {void}
	 */
	_startEdit(event) {
		if (this._isEditing) {
			return;
		}
		this._unselect();
		this._isEditing = true;
		const cell = TableCellEditable.getFromEvent(event);
		cell.startEdit();
	}

	/**
	 * @param {TableCellEditable} cell
	 * @returns {Promise<void>}
	 */
	async _completeEdit(cell) {
		try {
			const tr = cell.getRow();
			if (this._updatedCellValueCallback) {
				const rowId = tr.dataset.rowId;
				const columnName = cell.dataset.columnName;
				if (rowId === undefined || columnName === undefined) {
					throw new Error("Could not get rowId or columnName for edited cell");
				}
				/** @type {string|number|boolean} */
				let value = cell.value;
				const type = this._columns.find(column => column.name === columnName)?.type;
				if (type === undefined) {
					throw new Error("Could not get type for columnName");
				}
				switch (type) {
					case "number":
						value = parseInt(value, 10);
						if (isNaN(value) || value.toString() !== cell.value) {
							throw new Error(`value '${value}' is not a valid number`);
						}
						break;
					case "boolean":
						if (value === "1") {
							value = true;
						} else if (value === "0") {
							value = false;
						} else {
							throw new Error(`value '${value}' must be 0 or 1`);
						}
						break;
					default:
						break;
				}
				await this._updatedCellValueCallback(parseInt(rowId, 10), columnName, value);
				cell.completeEdit();
			} else {
				cell.completeEdit();
			}
		} catch (error) {
			console.error("Unexpected error in _completeEdit():", error);
			cell.cancelEdit();
		}
	}

	/**
	 * @param {FocusEvent} event
	 * @returns {void}
	 */
	_stopEditFocusout(event) {
		if (!this._isEditing) {
			return;
		}
		this._isEditing = false;
		const cell = TableCellEditable.getFromEvent(event);
		this._completeEdit(cell);
	}

	/**
	 * @param {KeyboardEvent} event
	 * @returns {void}
	 */
	_stopEditKeydown(event) {
		if (!this._isEditing) {
			return;
		}
		const cell = TableCellEditable.getFromEvent(event);
		switch (event.key) {
			case "Escape":
				this._isEditing = false;
				cell.cancelEdit();
				break;
			case "Enter":
				this._isEditing = false;
				this._completeEdit(cell);
				break;
			default:
		}
	}
}
