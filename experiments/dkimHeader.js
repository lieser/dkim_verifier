/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./dkimHeader.d.ts" />
///<reference path="./mozilla.d.ts" />
///<reference path="./mozillaDom.d.ts" />
/* global ExtensionCommon */

"use strict";

/** @type {{ExtensionParent: ExtensionParentM}} */
const { ExtensionParent } = ChromeUtils.import("resource://gre/modules/ExtensionParent.jsm");
/** @type {{ExtensionSupport: ExtensionSupportM}} */
const { ExtensionSupport } = ChromeUtils.import("resource:///modules/ExtensionSupport.jsm");

/**
 * Wraps an element in the given wrapper.
 * Note: element musst have a parent.
 *
 * @param {HTMLElement} element
 * @param {HTMLElement} wrapper
 */
function wrap(element, wrapper) {
	element.insertAdjacentElement("beforebegin", wrapper);
	wrapper.appendChild(element);
}

/**
 * Unwraps all child nodes in a given wrapper.
 * Note: wrapper musst have a parent.
 *
 * @param {HTMLElement} wrapper
 */
function unwrap(wrapper) {
	const parent = wrapper.parentNode;
	if (!parent) {
		throw Error("Wrapper element has no parent");
	}
	while (wrapper.firstChild) {
		parent.insertBefore(wrapper.firstChild, wrapper);
	}
	wrapper.remove();
}

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
		/**
		 * Whether a separator should be added before the warnings.
		 *
		 * @protected
		 */
		this._warningsSeparator = false;

		if (element) {
			// @ts-expect-error
			this.element = element;
			return;
		}
		/** @type {DKIMTooltipElement} */
		// @ts-expect-error
		this.element = document.createXULElement("tooltip");

		// A box containing the warnings
		this.element._warningsBox = document.createXULElement("vbox");
	}

	/**
	 * Set the warnings for the tooltip.
	 *
	 * @param {string[]} warnings
	 * @memberof DKIMTooltip
	 */
	set warnings(warnings) {
		// delete old warnings from tooltips
		this.element._warningsBox.replaceChildren();

		if (!this.element.ownerDocument) {
			throw Error("Underlying element of DKIMTooltip does not contain ownerDocument");
		}

		if (this._warningsSeparator && warnings.length) {
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
 * @augments {DKIMTooltip}
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
 * @augments {DKIMTooltip}
 */
class DkimResultTooltip extends DKIMTooltip {
	/**
	 * Creates an instance of DkimResultTooltip.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
	 * @memberof DKIMTooltip
	 */
	constructor(document, element) {
		super(document, element);
		/** @protected */
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
	 * Set the DKIM result.
	 *
	 * @param {string} val
	 * @memberof DKIMTooltip
	 */
	set value(val) {
		if (!this.element._value) {
			throw Error("Underlying element of DkimResultTooltip does not contain _value");
		}
		this.element._value.textContent = val;
	}
}

/**
 * The content that is shown inside the DkimHeaderRow.
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
			// @ts-expect-error
			this.element = element;
			this._dkimWarningTooltip = new DKIMWarningsTooltip(document, this.element._dkimWarningTooltip);
			return;
		}
		/** @type {DKIMHeaderFieldElement} */
		// @ts-expect-error
		this.element = document.createElement("div");
		this.element.id = DKIMHeaderField._id;

		const headerValue = document.createElement("div");
		headerValue.classList.add("headerValue");
		// Needed for TB < 96
		headerValue.style.display = "flex";
		headerValue.style.alignItems = "center";
		// TB >= 99 sets "wrap" for the "headerValue" class
		headerValue.style.flexWrap = "nowrap";

		// DKIM result
		this.element._dkimValue = document.createElement("span");
		this.element._dkimValue.style.userSelect = "text";

		// DKIM warning icon
		/** @private */
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
		 * Create element for ARH result.
		 *
		 * @param {string} anonid
		 * @param {string} labelValue
		 * @returns {{box: XULElement, value: XULElement}}
		 */
		function createArh(anonid, labelValue) {
			const box = document.createElement("div");
			box.setAttribute("anonid", anonid);
			box.style.marginInlineStart = "10px";

			const label = document.createElement("label");
			// The space is needed for a line break in between the label and span to occur.
			// Setting the span to "inline-block" has a similar result,
			// but would result in the span being completely on the second line if wrapping occurs.
			label.textContent = `${labelValue} `;

			const value = document.createElement("span");
			value.style.userSelect = "text";

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

		headerValue.appendChild(this.element._dkimValue);
		headerValue.appendChild(this.element._dkimWarningIcon);
		headerValue.appendChild(this.element._arhDkim.box);
		headerValue.appendChild(this.element._arhSpf.box);
		headerValue.appendChild(this.element._arhDmarc.box);
		this.element.appendChild(this.element._dkimWarningTooltip);
		this.element.appendChild(headerValue);

		this.reset();
	}

	/**
	 * Set the DKIM result.
	 *
	 * @param {string} val
	 * @memberof DKIMHeaderField
	 */
	set value(val) {
		this.element._dkimValue.textContent = val;
	}

	/**
	 * Set the DKIM warnings.
	 *
	 * @param {string[]} warnings
	 * @memberof DKIMHeaderField
	 */
	set warnings(warnings) {
		if (warnings.length) {
			this.element._dkimWarningIcon.style.display = "";
		} else {
			this.element._dkimWarningIcon.style.display = "none";
		}
		this._dkimWarningTooltip.warnings = warnings;
	}

	/**
	 * Set the SPF result.
	 *
	 * @param {string} val
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
	 * Set the DMARC result.
	 *
	 * @param {string} val
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
	 * Set the DKIM result from the ARH.
	 *
	 * @param {string} val
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
 * The DKIM row shown in the e-mail header.
 */
class DkimHeaderRow {
	/**
	 * Creates an instance of DkimHeaderRow.
	 *
	 * @param {Document} document
	 * @param {HTMLElement} element - optional underlying element, will be created if not given
	 * @memberof DkimHeaderRow
	 */
	constructor(document, element) {
		this.document = document;
		this.element = element;
	}

	/**
	 * Set whether the DKIM heder should be shown.
	 *
	 * @param {boolean} show
	 * @returns {void}
	 * @memberof DkimHeaderRow
	 */
	show(show) {
		if (show) {
			this.element.style.display = "";
		} else {
			this.element.style.display = "none";
		}
		// Trigger the OnResizeExpandedHeaderView() function from Thunderbird
		// to recalculate the height on the expandedHeaderView element in TB<=98.
		const defaultView = this.document.defaultView;
		if (defaultView) {
			const window = defaultView.window;
			if (window.OnResizeExpandedHeaderView) {
				window.OnResizeExpandedHeaderView();
			}
		}
	}

	/**
	 * Get the DKIM header row in a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {DkimHeaderRow}
	 * @memberof DkimHeaderRow
	 */
	static get(document) {
		const element = document.getElementById(DkimHeaderRow._id);
		if (!element) {
			throw Error("Could not find the DkimHeaderRow element");
		}
		return new DkimHeaderRow(document, element);
	}

	/**
	 * Add the DKIM header row to a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {void}
	 * @memberof DkimHeaderRow
	 */
	static add(document) {
		let headerRowElement;
		let headerRowContainer = document.getElementById("expandedHeaders2");
		if (headerRowContainer) {
			headerRowElement = this._createTableRowElement(document);
		} else {
			headerRowContainer = document.getElementById("extraHeadersArea");
			if (!headerRowContainer) {
				throw Error("Could not find the expandedHeaders2 element");
			}
			headerRowElement = this._createDivRowElement(document);
		}
		const headerRow = new DkimHeaderRow(document, headerRowElement);
		headerRow.show(false);
		headerRowContainer.appendChild(headerRow.element);
	}

	/**
	 * Remove the DKIM header row from a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {void}
	 * @memberof DkimHeaderRow
	 */
	static remove(document) {
		const headerRow = DkimHeaderRow.get(document);
		if (headerRow) {
			headerRow.element.remove();
		}
	}

	/**
	 * Create a table based header row element.
	 * Used in TB 78-95.
	 * Should be added to the `expandedHeaders2` element.
	 *
	 * @static
	 * @private
	 * @param {Document} document
	 * @returns {HTMLElement}
	 * @memberof DkimHeaderRow
	 */
	static _createTableRowElement(document) {
		const headerRow = document.createElement("tr");
		headerRow.id = DkimHeaderRow._id;

		const headerRowTitle = document.createElement("th");
		const headerRowTitleLabel = document.createXULElement("label");
		headerRowTitleLabel.classList.add("headerName");
		headerRowTitleLabel.textContent = "DKIM";
		headerRowTitle.appendChild(headerRowTitleLabel);

		const headerRowValue = document.createElement("td");
		const dkimHeaderField = new DKIMHeaderField(document);
		headerRowValue.appendChild(dkimHeaderField.element);

		headerRow.appendChild(headerRowTitle);
		headerRow.appendChild(headerRowValue);
		return headerRow;
	}

	/**
	 * Create a div based header row element.
	 * Used in TB >= 96.
	 * Should be added to the `extraHeadersArea` element.
	 *
	 * @static
	 * @private
	 * @param {Document} document
	 * @returns {HTMLElement}
	 * @memberof DkimHeaderRow
	 */
	static _createDivRowElement(document) {
		const headerRow = document.createElement("div");
		headerRow.id = DkimHeaderRow._id;
		headerRow.classList.add("message-header-row");

		// const headerRowLabel = document.createXULElement("label");
		const headerRowLabel = document.createElement("label");
		headerRowLabel.classList.add("message-header-label");
		headerRowLabel.textContent = "DKIM";

		const headerRowValue = document.createElement("div");
		headerRowValue.classList.add("headerValue");
		const dkimHeaderField = new DKIMHeaderField(document);
		headerRowValue.appendChild(dkimHeaderField.element);

		headerRow.appendChild(headerRowLabel);
		headerRow.appendChild(headerRowValue);
		return headerRow;
	}
}
DkimHeaderRow._id = "expandedDkim-verifierRow";

/**
 * The favicon shown before the from address.
 */
class DkimFavicon {
	/**
	 * Creates an instance of DkimFavicon.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
	 * @memberof DkimFavicon
	 */
	constructor(document, element) {
		if (element) {
			// @ts-expect-error
			this.element = element;
			this._dkimTooltipFrom = new DkimResultTooltip(document, this.element._dkimTooltipFromElement);
			return;
		}

		/** @type {DKIMFaviconElement} */
		// @ts-expect-error
		this.element = document.createXULElement("description");

		this.element.id = DkimFavicon._id;
		this.element.classList.add("headerValue");
		this.element.setAttribute("tooltip", DkimFavicon.idTooltip);
		// dummy text for align baseline
		this.element.textContent = "";
		this.element.style.setProperty("min-width", "0px", "important");
		this.element.style.width = "1.5em";
		this.element.style.height = "1.5em";
		this.element.style.backgroundSize = "contain";
		this.element.style.backgroundPosition = "center center";
		this.element.style.backgroundRepeat = "no-repeat";

		// DKIM tooltip
		/** @private */
		this._dkimTooltipFrom = new DkimResultTooltip(document);
		this.element._dkimTooltipFromElement = this._dkimTooltipFrom.element;
		this.element._dkimTooltipFromElement.id = DkimFavicon.idTooltip;
		this.element.setAttribute("tooltip", DkimFavicon.idTooltip);

		this.reset();
	}

	/**
	 * Set the DKIM result.
	 *
	 * @param {string} val
	 * @memberof DkimFavicon
	 */
	set value(val) {
		this._dkimTooltipFrom.value = val;
	}

	/**
	 * Set the DKIM warnings.
	 *
	 * @param {string[]} warnings
	 * @memberof DkimFavicon
	 */
	set warnings(warnings) {
		this._dkimTooltipFrom.warnings = warnings;
	}

	/**
	 * Sets the url to the favicon. Empty string to reset it.
	 *
	 * @param {string} faviconUrl
	 * @returns {void}
	 * @memberof DkimFavicon
	 */
	setFaviconUrl(faviconUrl) {
		this.element.style.backgroundImage = `url('${faviconUrl}')`;
		if (faviconUrl) {
			this.element.style.display = "";
		} else {
			this.element.style.display = "none";
		}
	}

	reset() {
		this.setFaviconUrl("");
		this.value = DKIMHeaderField.resetValue;
		this.warnings = [];
	}

	/**
	 * Get the DKIM favicon in a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {DkimFavicon}
	 * @memberof DkimFavicon
	 */
	static get(document) {
		const element = document.getElementById(DkimFavicon._id);
		if (!element) {
			throw Error("Could not find the DkimFavicon element");
		}
		return new DkimFavicon(document, element);
	}

	/**
	 * Add the DKIM favicon to a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {void}
	 * @memberof DkimFavicon
	 */
	static add(document) {
		const favicon = new DkimFavicon(document);
		// eslint-disable-next-line no-extra-parens
		const expandedFromBox = /** @type {expandedfromBox?} */ (document.getElementById("expandedfromBox"));
		if (!expandedFromBox) {
			throw Error("Could not find the expandedFromBox element");
		}

		// Add the favicon.
		if ("recipientsList" in expandedFromBox) {
			// TB >=102
			const hboxWrapper = document.createElement("div");
			favicon.element._hboxWrapper = hboxWrapper;
			hboxWrapper.style.display = "flex";
			hboxWrapper.style.alignItems = "center";

			favicon.element.style.marginInlineEnd = "var(--message-header-field-offset)";

			hboxWrapper.appendChild(favicon.element);
			wrap(expandedFromBox.recipientsList, hboxWrapper);
		} else {
			// TB <102
			expandedFromBox.prepend(favicon.element);
		}

		// Add the tooltip used by the favicon and the from address.
		// As the tooltip is reused, it can not be defined directly under the favicon.
		if ("longEmailAddresses" in expandedFromBox) {
			// TB <102
			expandedFromBox.longEmailAddresses.prepend(favicon._dkimTooltipFrom.element);
		} else {
			// TB >=102
			expandedFromBox.prepend(favicon._dkimTooltipFrom.element);
		}
	}

	/**
	 * Remove the DKIM favicon from a given document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {void}
	 * @memberof DkimFavicon
	 */
	static remove(document) {
		const favicon = DkimFavicon.get(document);
		if (favicon) {
			if (favicon.element._hboxWrapper) {
				unwrap(favicon.element._hboxWrapper);
			}
			favicon.element.remove();
			favicon._dkimTooltipFrom.element.remove();
		}
	}

	/**
	 * @private
	 * @readonly
	 */
	static _id = "dkimFavicon";
	/** @readonly */
	static idTooltip = "dkim-verifier-header-tooltip-from";
}

/**
 * DKIM specific modifications of the from address:
 * - Highlighting of the from address (text & background color)
 * - Show DKIM tooltip
 */
class DkimFromAddress {
	/**
	 * Get the element containing the from address (without the following star).
	 *
	 * @static
	 * @private
	 * @param {Document} document
	 * @returns {HTMLElement?}
	 */
	static _getFromAddress(document) {
		// TB >=102
		const fromRecipient0Display = document.getElementById("fromRecipient0Display");
		if (fromRecipient0Display) {
			return fromRecipient0Display;
		}

		// TB <102
		// eslint-disable-next-line no-extra-parens
		const expandedFromBox = /** @type {expandedfromBox?} */ (document.getElementById("expandedfromBox"));
		if (!expandedFromBox) {
			console.debug("DKIM: from address not found (no expandedfromBox)");
			return null;
		}
		if (!("emailAddresses" in expandedFromBox)) {
			console.debug("DKIM: from address not found (no expandedFromBox.emailAddresses)");
			return null;
		}
		const mailEmailadress = expandedFromBox.emailAddresses.firstElementChild;
		if (!mailEmailadress) {
			console.debug("DKIM: from address not found (no firstElementChild)");
			return null;
		}
		const emailValue = mailEmailadress.getElementsByClassName("emaillabel")[0];
		if (!emailValue) {
			console.debug("DKIM: from address not found (no emaillabel)");
			return null;
		}
		// eslint-disable-next-line no-extra-parens
		return /** @type {HTMLElement} */ (emailValue);
	}

	/**
	 * Set the text and background color of the from address.
	 *
	 * @param {Document} document
	 * @param {string} color
	 * @param {string} backgroundColor
	 * @returns {void}
	 */
	static setHighlightColor(document, color, backgroundColor) {
		const emailValue = this._getFromAddress(document);
		if (!emailValue) {
			return;
		}
		emailValue.style.borderRadius = "3px";
		emailValue.style.color = color;
		emailValue.style.backgroundColor = backgroundColor;
	}

	/**
	 * Set whether the DKIM tooltip should be shown.
	 *
	 * @param {Document} document
	 * @param {boolean} show
	 * @returns {void}
	 */
	static showTooltip(document, show) {
		const emailValue = this._getFromAddress(document);
		if (!emailValue) {
			return;
		}
		if (show) {
			// save current tooltip if set
			const tooltiptext = emailValue.getAttribute("tooltiptext");
			if (tooltiptext) {
				emailValue.setAttribute("tooltiptextSaved", tooltiptext);
			}
			emailValue.removeAttribute("tooltiptext");
			// set DKIM tooltip
			emailValue.setAttribute("tooltip", DkimFavicon.idTooltip);
		} else {
			if (emailValue.getAttribute("tooltip") === DkimFavicon.idTooltip) {
				// remove DKIM tooltip
				emailValue.removeAttribute("tooltip");
				// restore saved tooltip
				const tooltiptextSaved = emailValue.getAttribute("tooltiptextSaved");
				if (tooltiptextSaved) {
					emailValue.setAttribute("tooltiptext", tooltiptextSaved);
					emailValue.removeAttribute("tooltiptextSaved");
				}
			}
		}
	}

	/**
	 * Reset the DKIM specific modifications of the from address.
	 *
	 * @param {Document} document
	 * @returns {void}
	 */
	static reset(document) {
		this.setHighlightColor(document, "", "");
		this.showTooltip(document, false);
	}
}

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
			console.error("MessageListener.register(): already registered");
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
		const listener = DkimResetMessageListener._mapping.get(window);
		if (!listener) {
			console.error("MessageListener.unregister(): could not find a listener for the window");
			return;
		}
		const pos = window.gMessageListeners.indexOf(listener);
		if (pos !== -1) {
			window.gMessageListeners.splice(pos, 1);
		} else {
			console.error("MessageListener.unregister(): could not find the listener");
		}
		DkimResetMessageListener._mapping.delete(window);
	}

	/**
	 * Reset the header in a specific document.
	 *
	 * @static
	 * @param {Document} document
	 * @returns {void}
	 */
	static reset(document) {
		const dkimHeaderField = DKIMHeaderField.get(document);
		dkimHeaderField.reset();
		const dkimFavicon = DkimFavicon.get(document);
		dkimFavicon.reset();
		DkimFromAddress.reset(document);
	}

	onStartHeaders() {
		try {
			const document = this.window.document;
			DkimResetMessageListener.reset(document);
		} catch (error) {
			console.error("DKIM: Error in onStartHeaders:", error);
		}
	}
	// eslint-disable-next-line no-empty-function
	onEndHeaders() { }
	// eslint-disable-next-line no-empty-function
	onEndAttachments() { }

	/**
	 * @private
	 * @type {Map<Window, DkimResetMessageListener>}
	 */
	static _mapping = new Map();
}

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
		DkimHeaderRow.add(document);
		if (window.syncGridColumnWidths) {
			// TB <102
			window.syncGridColumnWidths();
		} else if (window.updateExpandedView) {
			// TB >=102
			// Calling `gMessageHeader.syncLabelsColumnWidths()` directly is not possible,
			// as `gMessageHeader` is not part of the `window` object.
			window.updateExpandedView();
		} else {
			console.warn("DKIM: Function to sync header column widths not found.");
		}
		DkimFavicon.add(document);
	}

	/**
	 * Remove the DKIM specific elements from the window.
	 *
	 * @param {Window} window
	 * @returns {void}
	 */
	unPaint(window) {
		const { document } = window;
		DkimHeaderRow.remove(document);
		DkimFavicon.remove(document);
	}

	/**
	 * Get the Document for a specific message shown in a tab.
	 * Returns null if a different message is shown.
	 *
	 * @param {number} tabId
	 * @param {number} messageId
	 * @returns {Document?}
	 */
	getDocumentForCurrentMsg(tabId, messageId) {
		const target = ExtensionParent.apiManager.global.tabTracker.getTab(tabId);
		const window = Cu.getGlobalForObject(target);
		const msg = this.extension.messageManager.convert(
			window.gFolderDisplay.selectedMessage);
		if (msg.id !== messageId) {
			return null;
		}
		return window.document;
	}

	/**
	 * @param {ExtensionCommon.Context} _context
	 * @returns {{dkimHeader: browser.dkimHeader}}
	 */
	getAPI(_context) {
		return {
			dkimHeader: {
				showDkimHeader: (tabId, messageId, show) => {
					const document = this.getDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					const dkimHeaderRow = DkimHeaderRow.get(document);
					dkimHeaderRow.show(show);

					return Promise.resolve(true);
				},
				showFromTooltip: (tabId, messageId, show) => {
					const document = this.getDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					DkimFromAddress.showTooltip(document, show);

					return Promise.resolve(true);
				},
				setDkimHeaderResult: (tabId, messageId, result, warnings, faviconUrl, arh) => {
					const document = this.getDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					const dkimHeaderField = DKIMHeaderField.get(document);
					dkimHeaderField.value = result;
					dkimHeaderField.warnings = warnings;
					if (arh.dkim) {
						dkimHeaderField.arhDkimValue = arh.dkim;
					}
					if (arh.spf) {
						dkimHeaderField.spfValue = arh.spf;
					}
					if (arh.dmarc) {
						dkimHeaderField.dmarcValue = arh.dmarc;
					}

					const favicon = DkimFavicon.get(document);
					favicon.value = result;
					favicon.warnings = warnings;
					favicon.setFaviconUrl(faviconUrl);

					return Promise.resolve(true);
				},
				highlightFromAddress: (tabId, messageId, color, backgroundColor) => {
					const document = this.getDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					DkimFromAddress.setHighlightColor(document, color, backgroundColor);

					return Promise.resolve(true);
				},
				reset: (tabId, messageId) => {
					const document = this.getDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					DkimResetMessageListener.reset(document);

					return Promise.resolve(true);
				},
			},
		};
	}
};
