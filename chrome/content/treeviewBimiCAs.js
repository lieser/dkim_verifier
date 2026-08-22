// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* global Components */
/* global BIMIDB, SQLiteTreeView */
/* exported setView, changeSelection, addBimiCA, removeBimiCA, setBimiCATrust, viewDetails */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

var DKIM_Verifier = {};
Cu.import("resource://dkim_verifier/logging.jsm.js", DKIM_Verifier);
Cu.import("resource://dkim_verifier/SQLiteTreeView.jsm.js");
Cu.import("resource://dkim_verifier/bimi.jsm.js");

var log = DKIM_Verifier.Logging.getLogger("Options");

var treeView;
var columns;

function setView() {
	"use strict";
	treeView = new SQLiteTreeView("dkimBimi.sqlite", "certs", ["commonName","fingerprint","expireson","trusted","internal"], null);
	document.getElementById('my-tree').view = treeView;
	columns = document.getElementById('my-tree').columns;
}

function changeSelection() {
	"use strict";
	let internalCol = columns.getNamedColumn("internal");
	let removeCABtn = document.getElementById("removeCABtn");
	let setCATrustBtn = document.getElementById("setCATrustBtn");
	let viewDetailsBtn = document.getElementById("viewDetailsBtn");
	let customSelected = false;
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i) && treeView.getCellText(i, internalCol) === "0") {
			customSelected = true;
			break; // in case of a multi selection
		}
	}
	removeCABtn.disabled = !customSelected;
	setCATrustBtn.disabled = !customSelected;
	viewDetailsBtn.disabled = treeView.selection.count === 0;
}

async function addBimiCA() {
	"use strict";

	const fileDlg = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
	fileDlg.init(window, "", Ci.nsIFilePicker.modeOpen);
	fileDlg.appendFilter("Certificates", "*.crt;*.cer");
	fileDlg.appendFilters(Ci.nsIFilePicker.filterAll);
	fileDlg.show();

	if (fileDlg.file) {
		let bytes;
		try {
			const inputStream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(Ci.nsIFileInputStream);
			inputStream.init(fileDlg.file, 1, 0, 0);
			const binaryStream = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
			binaryStream.setInputStream(inputStream);
			bytes = binaryStream.readByteArray(inputStream.available());
			binaryStream.close();
			inputStream.close();
		} catch (error) {
			log.error("Error reading certificate from file", error);
			return;
		}

		let binaryString = String.fromCharCode.apply(null, bytes);
		let base64Str = binaryString.match(/-----BEGIN [A-Z0-9 ]+-----/) ? binaryString : btoa(binaryString);
		base64Str = base64Str.replace(/-----BEGIN [A-Z0-9 ]+-----/g, '');
		base64Str = base64Str.replace(/-----END [A-Z0-9 ]+-----/g, '');
		base64Str = base64Str.replace(/\s+/g, '');

		const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
		try {
			const certObj = certDB.constructX509FromBase64(base64Str);
			if (certObj.certType === Ci.nsIX509Cert.CA_CERT) {
				await BIMIDB.addCA(base64Str, true);
				treeView.update(1);
				changeSelection();
			}
		} catch (error) {
			log.error("The certificate file is corrupt", error);
		}
	}
}

async function removeBimiCA() {
	"use strict";
	let internalCol = columns.getNamedColumn("internal");
	let fingerprintCol = columns.getNamedColumn("fingerprint");
	let toRemove = [];
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i) && treeView.getCellText(i, internalCol) === "0") {
			let fingerprint = treeView.getCellText(i, fingerprintCol);
			toRemove.push(fingerprint);
		}
	}
	for (const ca of toRemove) {
		await BIMIDB.removeCA(ca);
	}
	treeView.update(-1 * toRemove.length);
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
	treeView.update(0);
}

async function viewDetails() {
	"use strict";
	let fingerprintCol = columns.getNamedColumn("fingerprint");
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i)) {
			let fingerprint = treeView.getCellText(i, fingerprintCol);
			const certData = await BIMIDB.getCA(fingerprint);
			if (certData) {
				const certDialogs = Cc["@mozilla.org/nsCertificateDialogs;1"].getService(Ci.nsICertificateDialogs);
				const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
				try {
					const certObj = certDB.constructX509FromBase64(certData);
					certDialogs.viewCert(window, certObj);
				} catch (error) {
					log.error("The certificate file is corrupt", error);
				}
				break;
			}
		}
	}
}