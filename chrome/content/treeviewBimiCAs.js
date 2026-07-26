// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* global Components */
/* global BIMIDB, SQLiteTreeView */
/* exported setView, changeSelection, addBimiCA, removeBimiCA, setBimiCATrust */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://dkim_verifier/SQLiteTreeView.jsm.js");
Cu.import("resource://dkim_verifier/bimi.jsm.js");

var treeView;
var columns;

function setView() {
	"use strict";
	treeView = new SQLiteTreeView("dkimBimi.sqlite", "certs", ["commonName","fingerprint","trusted","internal"], null);
	document.getElementById('my-tree').view = treeView;
	columns = document.getElementById('my-tree').columns;
}

function changeSelection() {
	"use strict";
	let internalCol = columns.getNamedColumn("internal");
	let removeCABtn = document.getElementById("removeCABtn");
	let setCATrustBtn = document.getElementById("setCATrustBtn");
	let modifiableSelected = false;
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i) && treeView.getCellText(i, internalCol) === "0") {
			modifiableSelected = true;
		}
	}
	removeCABtn.disabled = !modifiableSelected;
	setCATrustBtn.disabled = !modifiableSelected;
}

async function addBimiCA() {
	"use strict";

	const fileDlg = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
	fileDlg.init(window, "", Ci.nsIFilePicker.modeOpen);
	fileDlg.appendFilter("Certificates", "*.crt;*.cer");
	fileDlg.appendFilters(Ci.nsIFilePicker.filterAll);
	fileDlg.show();

	if (fileDlg.file) {
		const inputStream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(Ci.nsIFileInputStream);
		inputStream.init(fileDlg.file, 1, 0, 0);
		const binaryStream = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
		binaryStream.setInputStream(inputStream);

		let bytes = binaryStream.readByteArray(inputStream.available());
		binaryStream.close();
		inputStream.close();

		let binaryString = String.fromCharCode.apply(null, bytes);
		let base64Str = binaryString.match(/-----BEGIN [A-Z0-9 ]+-----/) ? binaryString : btoa(binaryString);
		base64Str = base64Str.replace(/-----BEGIN [A-Z0-9 ]+-----/g, '');
		base64Str = base64Str.replace(/-----END [A-Z0-9 ]+-----/g, '');
		base64Str = base64Str.replace(/\s+/g, '');

		const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
		const certObj = certDB.constructX509FromBase64(base64Str);
		if (certObj.certType === Ci.nsIX509Cert.CA_CERT) {
			await BIMIDB.addCA(base64Str, true);
			treeView.update();
			changeSelection();
		}
	}
}

async function removeBimiCA() {
	"use strict";
	let internalCol = columns.getNamedColumn("internal");
	let fingerprintCol = columns.getNamedColumn("fingerprint");
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i) && treeView.getCellText(i, internalCol) === "0") {
			let fingerprint = treeView.getCellText(i, fingerprintCol);
			await BIMIDB.removeCA(fingerprint);
		}
	}
	treeView.update();
	changeSelection();
}

async function setBimiCATrust() {
	"use strict";
	let internalCol = columns.getNamedColumn("internal");
	let fingerprintCol = columns.getNamedColumn("fingerprint");
	let trustCol = columns.getNamedColumn("trusted");
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i) && treeView.getCellText(i, internalCol) === "0") {
			let fingerprint = treeView.getCellText(i, fingerprintCol);
			let newTrustValue = treeView.getCellText(i, trustCol) === "0";
			await BIMIDB.setCATrust(fingerprint, newTrustValue);
		}
	}
	treeView.update();
}