/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="dkimHeader.d.ts" />
///<reference path="../mozillaDom.d.ts" />
/* eslint-env worker */
/* global ChromeUtils, Components, ExtensionCommon */

"use strict";

const { ExtensionParent } = ChromeUtils.import("resource://gre/modules/ExtensionParent.jsm");
/** @type {{ExtensionSupport: ExtensionSupportM}} */
const { ExtensionSupport } = ChromeUtils.import("resource:///modules/ExtensionSupport.jsm");

/**
 * Base class for DKIM tooltips
 */
class DKIMTooltip {
	/**
	 * Creates an instance of DKIMTooltip.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
	 * @memberof DKIMTooltip
	 */
	constructor(document, element) {
		// whether a separator should be added before the warnings
		this._warningsSeparator = false;

		if (element) {
			// @ts-ignore
			this.element = element;
			return;
		}
		/** @type {DKIMTooltipElement} */
		// @ts-ignore
		this.element = document.createXULElement("tooltip");

		// A box containing the warnings
		this.element._warningsBox = document.createXULElement("vbox");
	}

	/**
	 * Set the warnings for the tooltip
	 *
	 * @param {String[]} warnings
	 * @memberof DKIMTooltip
	 */
	set warnings(warnings) {
		// delete old warnings from tooltips
		while (this.element._warningsBox.firstChild) {
			this.element._warningsBox.removeChild(this.element._warningsBox.firstChild);
		}

		if (!this.element.ownerDocument) {
			throw Error("Underlying element of DKIMTooltip does not contain ownerDocument");
		}

		if (this._warningsSeparator && warnings.length > 0) {
			const sep = this.element.ownerDocument.createXULElement("separator");
			sep.setAttribute("class", "thin");
			this.element._warningsBox.appendChild(sep);
		}

		// add warnings to warning tooltip
		for (const w of warnings) {
			const des = this.element.ownerDocument.createXULElement("description");
			des.textContent = w;
			this.element._warningsBox.appendChild(des);
		}
	}
}

/**
 * Tooltip showing the DKIM warnings.
 *
 * @extends {DKIMTooltip}
 */
class DKIMWarningsTooltip extends DKIMTooltip {
	/**
	 * Creates an instance of DKIMWarningsTooltip.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
	 * @memberof DKIMTooltip
	 */
	constructor(document, element) {
		super(document, element);
		if (element) {
			return;
		}

		this.element.appendChild(this.element._warningsBox);
	}
}

/**
 * Tooltip showing both the DKIM result and the warnings.
 * The tooltip contains the label "DKIM:".
 *
 * @extends {DKIMTooltip}
 */
class DKIMTooltipFrom extends DKIMTooltip {
	/**
	 * Creates an instance of DKIMTooltipFrom.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
	 * @memberof DKIMTooltip
	 */
	constructor(document, element) {
		super(document, element);
		this._warningsSeparator = true;
		if (element) {
			return;
		}

		// Outer box and label
		const outerBox = document.createXULElement("hbox");
		const outerBoxLabel = document.createXULElement("label");
		outerBoxLabel.setAttribute("value", "DKIM:");

		// The inner box, containing the DKIM result and optional the warnings
		const innerBox = document.createXULElement("vbox");
		innerBox.setAttribute("flex", "1");

		// The DKIM result
		this.element._value = document.createXULElement("label");

		this.element.appendChild(outerBox);
		outerBox.appendChild(outerBoxLabel);
		outerBox.appendChild(innerBox);
		innerBox.appendChild(this.element._value);
		innerBox.appendChild(this.element._warningsBox);
	}

	/**
	 * Set the DKIM result
	 *
	 * @param {String} val
	 * @memberof DKIMTooltip
	 */
	set value(val) {
		if (!this.element._value) {
			throw Error("Underlying element of DKIMTooltipFrom does not contain _value");
		}
		this.element._value.textContent = val;
	}
}

/**
 * DKIM header field
 */
class DKIMHeaderField {
	/**
	 * Creates an instance of DKIMHeaderField.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
	 * @memberof DKIMHeaderField
	 */
	constructor(document, element) {
		if (element) {
			// @ts-ignore
			this.element = element;
			this._dkimWarningTooltip = new DKIMWarningsTooltip(document, this.element._dkimWarningTooltip);
			return;
		}
		/** @type {DKIMHeaderFieldElement} */
		// @ts-ignore
		this.element = document.createXULElement("hbox");

		this.element.id = DKIMHeaderField._id;
		this.element.classList.add("headerValueBox");
		this.element.setAttribute("context", "copyPopup");
		// @ts-ignore
		this.element.style.MozBoxAlign = "center";

		// DKIM result
		this.element._dkimValue = document.createXULElement("description");
		this.element._dkimValue.classList.add("headerValue");

		// DKIM warning icon
		this._dkimWarningTooltip = new DKIMWarningsTooltip(document);
		this.element._dkimWarningTooltip = this._dkimWarningTooltip.element;
		this.element._dkimWarningTooltip.id = "dkim-verifier-header-tooltip-warnings";
		this.element._dkimWarningIcon = document.createXULElement("image");
		this.element._dkimWarningIcon.classList.add("alert-icon");
		this.element._dkimWarningIcon.setAttribute("anonid", "dkimWarningIcon");
		this.element._dkimWarningIcon.setAttribute("tooltip", "dkim-verifier-header-tooltip-warnings");
		this.element._dkimWarningIcon.style.maxWidth = "1.2em";
		this.element._dkimWarningIcon.style.maxHeight = "1.2em";
		this.element._dkimWarningIcon.style.marginLeft = "1ex";

		/**
		 * Create element for ARH result
		 *
		 * @param {String} anonid
		 * @param {String} labelValue
		 * @returns {{box: XULElement, value: XULElement}}
		 */
		function createArh(anonid, labelValue) {
			const box = document.createXULElement("hbox");
			box.setAttribute("anonid", anonid);

			const label = document.createXULElement("description");
			label.classList.add("headerValue");
			label.setAttribute("style", "text-align: right");
			label.textContent = labelValue;

			const value = document.createXULElement("description");
			value.classList.add("headerValue");

			box.appendChild(label);
			box.appendChild(value);

			return {
				box: box,
				value: value,
			};
		}

		// ARH result
		this.element._arhDkim = createArh("arhDkim", "DKIM:");
		this.element._arhSpf = createArh("spf", "SPF:");
		this.element._arhDmarc = createArh("dmarc", "DMARC:");

		const separator = document.createXULElement("separator");
		separator.setAttribute("flex", "1");

		this.element.appendChild(this.element._dkimValue);
		this.element.appendChild(this.element._dkimWarningTooltip);
		this.element.appendChild(this.element._dkimWarningIcon);
		this.element.appendChild(this.element._arhDkim.box);
		this.element.appendChild(this.element._arhSpf.box);
		this.element.appendChild(this.element._arhDmarc.box);
		this.element.appendChild(separator);

		this.reset();
	}

	/**
	 * Set the DKIM result
	 *
	 * @param {String} val
	 * @memberof DKIMHeaderField
	 */
	set value(val) {
		this.element._dkimValue.textContent = val;
	}

	/**
	 * Set the DKIM warnings
	 *
	 * @param {String[]} warnings
	 * @memberof DKIMHeaderField
	 */
	set warnings(warnings) {
		if (warnings.length > 0) {
			this.element._dkimWarningIcon.style.display = "";
		} else {
			this.element._dkimWarningIcon.style.display = "none";
		}
		this._dkimWarningTooltip.warnings = warnings;
	}

	/**
	 * Set the SPF result
	 *
	 * @param {String} val
	 * @memberof DKIMHeaderField
	 */
	set spfValue(val) {
		if (val) {
			this.element._arhSpf.box.style.display = "";
		} else {
			this.element._arhSpf.box.style.display = "none";
		}
		this.element._arhSpf.value.textContent = val;
	}

	/**
	 * Set the DMARC result
	 *
	 * @param {String} val
	 * @memberof DKIMHeaderField
	 */
	set dmarcValue(val) {
		if (val) {
			this.element._arhDmarc.box.style.display = "";
		} else {
			this.element._arhDmarc.box.style.display = "none";
		}
		this.element._arhDmarc.value.textContent = val;
	}

	/**
	 * Set the DKIM result from the ARH
	 *
	 * @param {String} val
	 * @memberof DKIMHeaderField
	 */
	set arhDkimValue(val) {
		if (val) {
			this.element._arhDkim.box.style.display = "";
		} else {
			this.element._arhDkim.box.style.display = "none";
		}
		this.element._arhDkim.value.textContent = val;
	}

	reset() {
		this.value = DKIMHeaderField.resetValue;
		this.warnings = [];
		this.spfValue = "";
		this.dmarcValue = "";
		this.arhDkimValue = "";
	}

	/**
	 * Get the DKIM header field in a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {DKIMHeaderField}
	 * @memberof DKIMHeaderField
	 */
	static get(document) {
		const element = document.getElementById(DKIMHeaderField._id);
		if (!element) {
			throw Error("Could not find the DKIMHeaderField element");
		}
		return new DKIMHeaderField(document, element);
	}
}
DKIMHeaderField.resetValue = "Validating…";
DKIMHeaderField._id = "expandedDkim-verifierBox";

/**
 *
 *
 * @class DkimHeaderRow
 * @implements {HTMLElement}
 */
class DkimHeaderRow {
	/**
	 * Creates an instance of DkimHeaderRow.
	 * @param {Document} document
	 * @memberof DkimHeaderRow
	 */
	constructor(document) {
		this.element = document.createElement("tr");
		this.element.id = DkimHeaderRow._id;

		const headerRowTitle = document.createElement("th");
		const headerRowTitleLabel = document.createXULElement("label");
		headerRowTitleLabel.classList.add("headerName");
		headerRowTitleLabel.textContent = "DKIM";
		headerRowTitle.appendChild(headerRowTitleLabel);

		const headerRowValue = document.createElement("td");
		const dkimHeaderField = new DKIMHeaderField(document);
		headerRowValue.appendChild(dkimHeaderField.element);

		this.element.appendChild(headerRowTitle);
		this.element.appendChild(headerRowValue);
	}

	/**
	 * Get the DKIM header row in a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {HTMLElement}
	 * @memberof DkimHeaderRow
	 */
	static get(document) {
		const element = document.getElementById(DkimHeaderRow._id);
		if (!element) {
			throw Error("Could not find the DKIMHeaderField element");
		}
		return element;
	}
}
DkimHeaderRow._id = "expandedDkim-verifierRow";

/**
 * A listener on gMessageListeners that resets the DKIM related header elements.
 *
 * Functions will be called in the following order:
 * 1. onStartHeaders
 * 2. onBeforeShowHeaderPane (optional)
 * 3. onEndHeaders
 */
class DkimResetMessageListener {
	/**
	 * Creates an instance of DkimResetMessageListener.
	 * Should not be called directly, use the static register() instead.
	 *
	 * @param {Window} window
	 * @memberof DkimResetMessageListener
	 */
	constructor(window) {
		this.window = window;
	}

	/**
	 * Create and register a DkimResetMessageListener.
	 *
	 * @static
	 * @param {Window} window
	 * @returns {void}
	 * @memberof DkimResetMessageListener
	 */
	static register(window) {
		if (DkimResetMessageListener._mapping.has(window)) {
			console.warn("MessageListener.register(): already registered");
		}
		const messageListener = new DkimResetMessageListener(window);
		DkimResetMessageListener._mapping.set(window, messageListener);
		window.gMessageListeners.push(messageListener);
	}

	/**
	 * Unregister a DkimResetMessageListener.
	 *
	 * @static
	 * @param {Window} window
	 * @returns {void}
	 * @memberof DkimResetMessageListener
	 */
	static unregister(window) {
		const pos = window.gMessageListeners.indexOf(this);
		if (pos !== -1) {
			window.gMessageListeners.splice(pos, 1);
		} else {
			console.warn("MessageListener.unregister(): could not find the listener");
		}
		DkimResetMessageListener._mapping.delete(window);
	}

	onStartHeaders() {
		const dkimHeaderField = DKIMHeaderField.get(this.window.document);
		dkimHeaderField.reset();
	}
	// eslint-disable-next-line no-empty-function
	onEndHeaders() { }
	// eslint-disable-next-line no-empty-function
	onEndAttachments() { }
}
/** @type {Map<Window, DkimResetMessageListener>} */
DkimResetMessageListener._mapping = new Map();

// eslint-disable-next-line no-invalid-this
this.dkimHeader = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {ExtensionCommon.Extension} extension
	 */
	constructor(extension) {
		super(extension);

		this.id = `${extension.id}|dkimHeader`;
		this.windowURLs = [
			"chrome://messenger/content/messenger.xhtml",
			"chrome://messenger/content/messageWindow.xhtml",
		];

		DKIMHeaderField.resetValue = extension.localeData.localizeMessage("loading");

		extension.callOnClose(this);
		this.open();
	}

	open() {
		ExtensionSupport.registerWindowListener(this.id, {
			chromeURLs: this.windowURLs,
			onLoadWindow: window => {
				DkimResetMessageListener.register(window);
				this.paint(window);
			},
		});
	}

	close() {
		ExtensionSupport.unregisterWindowListener(this.id);
		for (const window of ExtensionSupport.openWindows) {
			if (this.windowURLs.includes(window.location.href)) {
				DkimResetMessageListener.unregister(window);
				this.unPaint(window);
			}
		}
	}

	/**
	 * Add the DKIM specific elements to the window.
	 *
	 * @param {Window} window
	 * @returns {void}
	 */
	paint(window) {
		const { document } = window;
		const headerRow = new DkimHeaderRow(document);
		const expandedHeaders2 = document.getElementById("expandedHeaders2");
		if (!expandedHeaders2) {
			throw Error("Could not find the expandedHeaders2 element");
		}
		expandedHeaders2.appendChild(headerRow.element);
	}

	/**
	 * Remove the DKIM specific elements from the window.
	 *
	 * @param {Window} window
	 * @returns {void}
	 */
	unPaint(window) {
		const headerRow = DkimHeaderRow.get(window.document);
		if (headerRow) {
			headerRow.remove();
		}
	}

	/**
	 * @param {ExtensionCommon.Context} context
	 * @returns {{dkimHeader: browser.dkimHeader}}
	 */
	// eslint-disable-next-line no-unused-vars
	getAPI(context) {
		const tabTracker = ExtensionParent.apiManager.global.tabTracker;
		return {
			dkimHeader: {
				setDkimHeaderResult: (tabId, result, warnings) => {
					const target = tabTracker.getTab(tabId);
					const { document } = Components.utils.getGlobalForObject(target);

					const dkimHeaderField = DKIMHeaderField.get(document);
					dkimHeaderField.value = result;
					dkimHeaderField.warnings = warnings;
				},
			}
		};
	}
};
