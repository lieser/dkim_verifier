/**
 * Copyright (c) 2020-2023 Philippe Lieser
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
 * The localized DKIM "loading" string.
 *
 * The default english value will be replaced by the localized one
 * then the experiment API gets constructed.
 */
let DKIMResultResetValue = "Validating…";

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
 * XUL tooltip showing the DKIM warnings.
 */
class DKIMWarningsTooltipXUL {
	/**
	 * Creates an instance of DKIMWarningsTooltipXUL.
	 *
	 * @param {Document} document
	 * @param {XULElement|void} element - optional underlying element, will be created if not given
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

		/** @type {DKIMWarningsTooltipXULElement} */
		// @ts-expect-error
		this.element = document.createXULElement("tooltip");

		// A box containing the warnings
		this.element._warningsBox = document.createXULElement("vbox");

		this.element.appendChild(this.element._warningsBox);
	}

	/**
	 * Set the warnings for the tooltip.
	 *
	 * @param {string[]} warnings
	 */
	set warnings(warnings) {
		if (!this.element._warningsBox) {
			throw Error("Underlying element of DKIMTooltipXUL does not contain _warningsBox");
		}

		// delete old warnings from tooltips
		this.element._warningsBox.replaceChildren();

		if (!this.element.ownerDocument) {
			throw Error("Underlying element of DKIMTooltipXUL does not contain ownerDocument");
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
 * Base class for DKIM tooltips.
 */
class DKIMTooltip {
	/**
	 * Creates an instance of DKIMTooltip.
	 *
	 * @param {Document} document
	 * @param {HTMLElement|void} element - optional underlying element, will be created if not given
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
		this.element = document.createElement("div");
		this.element.style.visibility = "hidden";
		this.element.style.position = "absolute";
		this.element.style.zIndex = "99";

		this.element.style.backgroundColor = "var(--arrowpanel-background)";
		this.element.style.color = "var(--arrowpanel-color)";
		this.element.style.borderStyle = "solid";
		this.element.style.borderWidth = "1px";
		this.element.style.borderColor = "var(--arrowpanel-border-color)";
		this.element.style.borderRadius = "var(--arrowpanel-border-radius)";
		this.element.style.paddingInline = "0.6em";
		this.element.style.paddingBlock = "0.4em";

		this.element._dkimOnmouseenter = (event) => DKIMTooltip.#mouseEnter(this, event);
		this.element._dkimOnmouseleave = (event) => DKIMTooltip.#mouseLeave(this, event);
	}

	/**
	 * Add the tooltip to the given target.
	 *
	 * @protected
	 * @param {DKIMTooltipTarget} target
	 */
	add(target) {
		if (target._dkimTooltip) {
			throw new Error("DKIM: A DKIMTooltip already exist on target");
		}
		if (this.element._target) {
			throw new Error("DKIM: The DKIMTooltip was already added to a target");
		}

		target._dkimTooltip = this.element;
		this.element._target = target;

		// The tooltip is added to the body instead of the target
		// to avoid potential issues with overflow.
		// See also
		// - https://stackoverflow.com/questions/36531708/why-does-position-absolute-make-page-to-overflow
		// - https://stackoverflow.com/questions/6421966/css-overflow-x-visible-and-overflow-y-hidden-causing-scrollbar-issue
		target.ownerDocument.body.appendChild(this.element);
		target.addEventListener("mouseenter", this.element._dkimOnmouseenter);
		target.addEventListener("mouseleave", this.element._dkimOnmouseleave);
	}

	/**
	 * Remove the tooltip.
	 *
	 * @protected
	 */
	remove() {
		const target = this.element._target;
		if (target) {
			target.removeEventListener("mouseenter", this.element._dkimOnmouseenter);
			target.removeEventListener("mouseleave", this.element._dkimOnmouseleave);
			delete target._dkimTooltip;
		}
		this.element.remove();
	}

	/**
	 * @param {DKIMTooltip} tooltip
	 * @param {MouseEvent} _event
	 */
	static #mouseEnter(tooltip, _event) {
		const target = tooltip.element._target;
		if (!target) {
			throw new Error("DKIM: mouseEnter event called for a DKIMTooltip that has no target");
		}

		// Avoid title being shown together with tooltip
		if (target?.title) {
			target.dataset.titleBackup = target.title;
			target.title = "";
		}

		// Calculate and set tooltip position
		const clientRect = target.getBoundingClientRect();
		const tooltipSpaceToTarget = 10;
		tooltip.element.style.top = `${clientRect.bottom + tooltipSpaceToTarget}px`;
		tooltip.element.style.left = `${clientRect.left}px`;

		// Show tooltip
		tooltip.element.style.visibility = "visible";
	}

	/**
	 * @param {DKIMTooltip} tooltip
	 * @param {MouseEvent} _event
	 */
	static #mouseLeave(tooltip, _event) {
		// Hide tooltip
		tooltip.element.style.visibility = "hidden";

		// Restore title
		const target = tooltip.element._target;
		if (target?.dataset.titleBackup) {
			target.title = target.dataset.titleBackup;
			target.dataset.titleBackup = "";
		}
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
	 * @param {HTMLElement|void} element - optional underlying element, will be created if not given
	 */
	constructor(document, element) {
		super(document, element);
		/** @protected */
		this._warningsSeparator = true;
		if (element) {
			return;
		}

		this.element.classList.add(DkimResultTooltip.#class);

		// Outer box and label
		const outerBox = document.createElement("div");
		outerBox.style.display = "grid";
		outerBox.style.gridTemplateColumns = "max-content auto";
		outerBox.style.width = "max-content";
		outerBox.style.maxWidth = "400px";
		const outerBoxLabel = document.createElement("p");
		outerBoxLabel.textContent = "DKIM:";
		outerBoxLabel.style.paddingInlineEnd = "0.4em";

		// The inner box, containing the DKIM result and optional the warnings
		const innerBox = document.createElement("div");

		// The DKIM result
		this.element._value = document.createElement("p");

		// A box containing the warnings
		this.element._warningsBox = document.createElement("div");

		this.element.appendChild(outerBox);
		outerBox.appendChild(outerBoxLabel);
		outerBox.appendChild(innerBox);
		innerBox.appendChild(this.element._value);
		innerBox.appendChild(this.element._warningsBox);

		this.reset();
	}

	/**
	 * Set the DKIM result.
	 *
	 * @param {string} val
	 */
	set value(val) {
		if (!this.element._value) {
			throw Error("Underlying element of DkimResultTooltip does not contain _value");
		}
		this.element._value.textContent = val;
	}

	/**
	 * Set the warnings for the tooltip.
	 *
	 * @param {string[]} warnings
	 */
	set warnings(warnings) {
		if (!this.element._warningsBox) {
			throw Error("Underlying element of DkimResultTooltip does not contain _warningsBox");
		}

		// delete old warnings from tooltips
		this.element._warningsBox.replaceChildren();

		if (!this.element.ownerDocument) {
			throw Error("Underlying element of DKIMTooltip does not contain ownerDocument");
		}

		if (this._warningsSeparator && warnings.length) {
			this.element._warningsBox.style.paddingBlock = "0.2em";
		} else {
			this.element._warningsBox.style.paddingBlock = "";
		}

		// add warnings to warning tooltip
		for (const w of warnings) {
			const des = this.element.ownerDocument.createElement("p");
			des.textContent = w;
			this.element._warningsBox.appendChild(des);
		}
	}

	reset() {
		this.value = DKIMResultResetValue;
		this.warnings = [];
	}

	/**
	 * Try getting the tooltip of a target.
	 *
	 * @param {DKIMTooltipTarget} target
	 * @returns {DkimResultTooltip|null}
	 */
	static get(target) {
		if (target._dkimTooltip) {
			return new DkimResultTooltip(target._dkimTooltip.ownerDocument, target._dkimTooltip);
		}
		return null;
	}

	/**
	 * Get all tooltips in the given document.
	 *
	 * @param {Document} document
	 * @returns {DkimResultTooltip[]}
	 */
	static getAll(document) {
		// eslint-disable-next-line no-extra-parens
		const elements = /** @type {HTMLElement[]} */ (
			Array.from(document.getElementsByClassName(DkimResultTooltip.#class)));
		const tooltips = [];
		for (const element of elements) {
			tooltips.push(new DkimResultTooltip(element.ownerDocument, element));
		}
		return tooltips;
	}

	/**
	 * Add a tooltip to the given target.
	 *
	 * @param {DKIMTooltipTarget} target
	 * @returns {DkimResultTooltip}
	 */
	static add(target) {
		const existingTooltip = DkimResultTooltip.get(target);
		if (existingTooltip) {
			console.warn("DKIM: DkimResultTooltip already exist and will be reused");
			return existingTooltip;
		}

		const tooltip = new DkimResultTooltip(target.ownerDocument);
		tooltip.add(target);
		return tooltip;
	}

	/**
	 * Remove an existing tooltip from the given target.
	 *
	 * @param {HTMLElement} target
	 */
	static remove(target) {
		const tooltip = DkimResultTooltip.get(target);
		tooltip?.remove();
	}

	static #class = "DkimResultTooltip";
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
	 */
	constructor(document, element) {
		if (element) {
			// @ts-expect-error
			this.element = element;
			this._dkimWarningTooltip = new DKIMWarningsTooltipXUL(document, this.element._dkimWarningTooltip);
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
		this._dkimWarningTooltip = new DKIMWarningsTooltipXUL(document);
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
				box,
				value,
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
	 */
	set value(val) {
		this.element._dkimValue.textContent = val;
	}

	/**
	 * Set the DKIM warnings.
	 *
	 * @param {string[]} warnings
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
		this.value = DKIMResultResetValue;
		this.warnings = [];
		this.spfValue = "";
		this.dmarcValue = "";
		this.arhDkimValue = "";
	}

	/**
	 * Get the DKIM header field in a given document.
	 *
	 * @param {Document} document
	 * @returns {DKIMHeaderField}
	 */
	static getOrThrow(document) {
		const element = document.getElementById(DKIMHeaderField._id);
		if (!element) {
			throw Error("Could not find the DKIMHeaderField element");
		}
		return new DKIMHeaderField(document, element);
	}
}
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
	 * @param {Document} document
	 * @returns {DkimHeaderRow|null}
	 */
	static get(document) {
		const element = document.getElementById(DkimHeaderRow._id);
		if (!element) {
			return null;
		}
		return new DkimHeaderRow(document, element);
	}

	/**
	 * Get the DKIM header row in a given document.
	 *
	 * @param {Document} document
	 * @returns {DkimHeaderRow}
	 */
	static getOrThrow(document) {
		const dkimHeaderRow = DkimHeaderRow.get(document);
		if (!dkimHeaderRow) {
			throw Error("Could not find the DkimHeaderRow element");
		}
		return dkimHeaderRow;
	}

	/**
	 * Add the DKIM header row to a given document.
	 *
	 * @param {Document} document
	 * @returns {void}
	 */
	static add(document) {
		let headerRowElement;
		let headerRowContainer = document.getElementById("expandedHeaders2");
		/** @type {InsertPosition|undefined} */
		let position;
		if (headerRowContainer) {
			// TB < 96
			headerRowElement = this.#createTableRowElement(document);
			position = "beforeend";
		} else {
			// TB >= 96
			headerRowContainer = document.getElementById("extraHeadersArea");
			if (!headerRowContainer) {
				throw Error("Could not find the expandedHeaders2 element");
			}
			headerRowElement = this.#createDivRowElement(document);
			position = "beforebegin";
		}
		const headerRow = new DkimHeaderRow(document, headerRowElement);
		headerRow.show(false);
		headerRowContainer.insertAdjacentElement(position, headerRow.element);
	}

	/**
	 * Remove the DKIM header row from a given document.
	 *
	 * @param {Document} document
	 * @returns {void}
	 */
	static remove(document) {
		const headerRow = DkimHeaderRow.get(document);
		if (headerRow) {
			headerRow.element.remove();
		}
	}

	/**
	 * Trigger syncing the column widths of all headers.
	 *
	 * @param {Window} window
	 */
	static syncColumns(window) {
		try {
			if (window.syncGridColumnWidths) {
				// TB <102
				window.syncGridColumnWidths();
			} else if (window.updateExpandedView) {
				// TB >=102
				// Calling `gMessageHeader.syncLabelsColumnWidths()` directly is not possible,
				// as `gMessageHeader` is not part of the `window` object.

				// When viewing messages in a window, `gFolderDisplay` is defined only in the first opened window.
				// A missing `gFolderDisplay` will result in `updateExpandedView()` to fail in older TB version.
				// In TB 111 this is not the case.
				try {
					window.updateExpandedView();
				} catch (error) {
					// ignore
				}
			} else {
				console.warn("DKIM: Function to sync header column widths not found.");
			}
		} catch (error) {
			console.warn("DKIM: Function to sync header column failed:", error);
		}
	}

	/**
	 * Create a table based header row element.
	 * Used in TB 78-95.
	 * Should be added to the `expandedHeaders2` element.
	 *
	 * @param {Document} document
	 * @returns {HTMLElement}
	 */
	static #createTableRowElement(document) {
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
	 * @param {Document} document
	 * @returns {HTMLElement}
	 */
	static #createDivRowElement(document) {
		const headerRow = document.createElement("div");
		headerRow.id = DkimHeaderRow._id;
		headerRow.classList.add("message-header-row");

		// We still use XUL and store the text in the value to get the same styling
		// as the original TB headers.
		// Otherwise in e.g. TB 102 the header text alignment for messages opened in a new tab differs.
		const headerRowLabel = document.createXULElement("label");
		headerRowLabel.classList.add("message-header-label");
		headerRowLabel.setAttribute("value", "DKIM");

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
	 */
	constructor(document, element) {
		if (element) {
			// @ts-expect-error
			this.element = element;
			this._dkimTooltipFrom = DkimResultTooltip.get(this.element);
			if (!this._dkimTooltipFrom) {
				console.warn("DKIM: DkimResultTooltip for DkimFavicon not found - will recreate it");
				this._dkimTooltipFrom = DkimResultTooltip.add(this.element);
			}
			return;
		}

		/** @type {DKIMFaviconElement} */
		// @ts-expect-error
		this.element = document.createXULElement("description");

		this.element.id = DkimFavicon.#id;
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
		this._dkimTooltipFrom = DkimResultTooltip.add(this.element);

		this.reset();
	}

	/**
	 * Sets the url to the favicon. Empty string to reset it.
	 *
	 * @param {string} faviconUrl
	 * @returns {void}
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
		this._dkimTooltipFrom.reset();
	}

	/**
	 * Get the DKIM favicon in a given document.
	 *
	 * @param {Document} document
	 * @returns {DkimFavicon|null}
	 */
	static get(document) {
		const element = document.getElementById(DkimFavicon.#id);
		if (!element) {
			return null;
		}
		return new DkimFavicon(document, element);
	}

	/**
	 * Get the DKIM favicon in a given document.
	 *
	 * @param {Document} document
	 * @returns {DkimFavicon}
	 */
	static getOrThrow(document) {
		const dkimFavicon = DkimFavicon.get(document);
		if (!dkimFavicon) {
			throw Error("Could not find the DkimFavicon element");
		}
		return dkimFavicon;
	}

	/**
	 * Add the DKIM favicon to a given document.
	 *
	 * @param {Document} document
	 * @returns {void}
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
	}

	/**
	 * Remove the DKIM favicon from a given document.
	 *
	 * @param {Document} document
	 * @returns {void}
	 */
	static remove(document) {
		const favicon = DkimFavicon.get(document);
		if (favicon) {
			if (favicon.element._hboxWrapper) {
				unwrap(favicon.element._hboxWrapper);
			}
			favicon.element.remove();
			DkimResultTooltip.remove(favicon.element);
		}
	}

	/**
	 * @readonly
	 */
	static #id = "dkimFavicon";
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
	 * Get the elements containing the from address (without the following star).
	 * Can return multiple elements, as newer Thunderbird version have
	 * both a single line and a multi line from address.
	 *
	 * @param {Document} document
	 * @returns {HTMLElement[]}
	 */
	static #getFromAddress(document) {
		// TB >=102
		const fromRecipient0Display = document.getElementById("fromRecipient0Display");
		if (fromRecipient0Display) {
			// eslint-disable-next-line no-extra-parens
			const fromRecipient0 = /** @type {HeaderRecipient?} */ (document.getElementById("fromRecipient0"));
			if (!fromRecipient0) {
				console.warn("DKIM: multi line from address not found (no fromRecipient0)");
			} else if (!fromRecipient0.multiLine) {
				console.warn("DKIM: multi line from address not found (fromRecipient0 has no multiLine)");
			} else {
				return [fromRecipient0Display, fromRecipient0.multiLine];
			}
			return [fromRecipient0Display];
		}

		// TB <102
		// eslint-disable-next-line no-extra-parens
		const expandedFromBox = /** @type {expandedfromBox?} */ (document.getElementById("expandedfromBox"));
		if (!expandedFromBox) {
			console.debug("DKIM: from address not found (no expandedfromBox)");
			return [];
		}
		if (!("emailAddresses" in expandedFromBox)) {
			console.debug("DKIM: from address not found (no expandedFromBox.emailAddresses)");
			return [];
		}
		const mailEmailadress = expandedFromBox.emailAddresses.firstElementChild;
		if (!mailEmailadress) {
			console.debug("DKIM: from address not found (no firstElementChild)");
			return [];
		}
		const emailValue = mailEmailadress.getElementsByClassName("emaillabel")[0];
		if (!emailValue) {
			console.debug("DKIM: from address not found (no emaillabel)");
			return [];
		}
		// eslint-disable-next-line no-extra-parens
		return [/** @type {HTMLElement} */ (emailValue)];
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
		const emailValues = this.#getFromAddress(document);
		if (!emailValues) {
			return;
		}
		for (const emailValue of emailValues) {
			emailValue.style.borderRadius = "3px";
			emailValue.style.color = color;
			emailValue.style.backgroundColor = backgroundColor;
		}
	}

	/**
	 * Set whether the DKIM tooltip should be shown.
	 *
	 * @param {Document} document
	 * @param {boolean} show
	 * @returns {void}
	 */
	static showTooltip(document, show) {
		const emailValues = this.#getFromAddress(document);
		if (!emailValues) {
			return;
		}
		for (const emailValue of emailValues) {
			if (show) {
				// save current XUL tooltip if set
				const tooltiptext = emailValue.getAttribute("tooltiptext");
				if (tooltiptext) {
					emailValue.setAttribute("tooltiptextSaved", tooltiptext);
				}
				emailValue.removeAttribute("tooltiptext");

				// set DKIM tooltip
				DkimResultTooltip.add(emailValue);
			} else {
				// remove DKIM tooltip
				DkimResultTooltip.remove(emailValue);

				// restore saved XUL tooltip
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
	 */
	constructor(window) {
		this.window = window;
	}

	/**
	 * Create and register a DkimResetMessageListener.
	 *
	 * @param {Window} window
	 * @returns {void}
	 */
	static register(window) {
		if (DkimResetMessageListener.#mapping.has(window)) {
			console.error("DkimResetMessageListener.register(): already registered");
		}
		const messageListener = new DkimResetMessageListener(window);
		DkimResetMessageListener.#mapping.set(window, messageListener);
		window.gMessageListeners.push(messageListener);
	}

	/**
	 * Unregister a DkimResetMessageListener.
	 *
	 * @param {Window} window
	 * @returns {void}
	 */
	static unregister(window) {
		const listener = DkimResetMessageListener.#mapping.get(window);
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
		DkimResetMessageListener.#mapping.delete(window);
	}

	/**
	 * Reset the header in a specific document.
	 *
	 * @param {Document} document
	 * @returns {void}
	 */
	static reset(document) {
		const dkimHeaderField = DKIMHeaderField.getOrThrow(document);
		dkimHeaderField.reset();
		const dkimFavicon = DkimFavicon.getOrThrow(document);
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
	 * @type {Map<Window, DkimResetMessageListener>}
	 */
	static #mapping = new Map();
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
		];

		DKIMResultResetValue = extension.localeData.localizeMessage("loading");

		extension.callOnClose(this);
		this.open();
	}

	/**
	 * From the top level window get the potential inner window there the headers are in.
	 *
	 * Note: Does not work with multiple tabs. Will only return the inner window
	 *       of the mail3Pane tab in the "normal" TB window.
	 *
	 * @param {Window} window
	 * @returns {Window}
	 */
	#getMessageBrowserWindow(window) {
		if (window.gMessageListeners) {
			// TB < 111
			return window;
		}

		// TB >= 111
		let msgViewDocument;
		// eslint-disable-next-line no-extra-parens
		const browser1 = /** @type {HTMLIFrameElement} */ (window.document.getElementById("mail3PaneTabBrowser1"));
		if (browser1) {
			// Window contains a tab with the mail3PaneTab
			msgViewDocument = browser1.contentDocument;
			if (!msgViewDocument) {
				throw new Error("DKIM: mail3PaneTabBrowser1 exists but does not contain a document");
			}
		} else {
			// Message is displayed in a new Window
			msgViewDocument = window.document;
		}

		// eslint-disable-next-line no-extra-parens
		const messageBrowser = /** @type {HTMLIFrameElement} */ (msgViewDocument.getElementById("messageBrowser"));
		const innerWindow = messageBrowser.contentWindow;
		if (!innerWindow) {
			throw new Error("DKIM: messageBrowser exists but does not contain a window");
		}
		return innerWindow;
	}

	open() {
		ExtensionSupport.registerWindowListener(this.id, {
			chromeURLs: this.windowURLs,
			onLoadWindow: window => {
				const messageBrowserWindow = this.#getMessageBrowserWindow(window);
				DkimResetMessageListener.register(this.#getMessageBrowserWindow(messageBrowserWindow));
			},
			onUnloadWindow: window => {
				const messageBrowserWindow = this.#getMessageBrowserWindow(window);
				DkimResetMessageListener.unregister(messageBrowserWindow);
			},
		});
	}

	close() {
		ExtensionSupport.unregisterWindowListener(this.id);
		for (const window of ExtensionSupport.openWindows) {
			try {
				if (this.windowURLs.includes(window.location.href)) {
					const messageBrowserWindow = this.#getMessageBrowserWindow(window);
					DkimResetMessageListener.unregister(messageBrowserWindow);
					this.unPaint(messageBrowserWindow);
				}

				// Remove added DKIM elements in all tabs
				const wrappedWindow = this.extension.windowManager.getWrapper(window);
				if (wrappedWindow) {
					const tabs = wrappedWindow.getTabs();
					for (const tab of tabs) {
						if (tab.type === "messageDisplay") {
							// messages opened in a new tab or window
							const { window: innerWindow } = this.#getWindowAndIdOfMsgShownInTab(tab.id);
							this.unPaint(innerWindow);
						}
					}
				}
			} catch (error) {
				console.error(`DKIM: cleanup for window ${window.document.title} failed`, error);
			}
		}
	}

	/**
	 * Add the DKIM specific elements to the window if needed.
	 *
	 * @param {Window} window
	 * @returns {void}
	 */
	paint(window) {
		const { document } = window;
		const dkimHeaderRow = DkimHeaderRow.get(document);
		if (!dkimHeaderRow) {
			DkimHeaderRow.add(document);
		}
		DkimHeaderRow.syncColumns(window);
		const dkimFavicon = DkimFavicon.get(document);
		if (!dkimFavicon) {
			DkimFavicon.add(document);
		}
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
		DkimFromAddress.reset(document);
	}

	/**
	 * Get the inner Window and id for a message shown in a tab.
	 *
	 * @param {number} tabId
	 * @returns {{window: Window, id: number|null}}
	 */
	#getWindowAndIdOfMsgShownInTab(tabId) {
		const tab = this.extension.tabManager.get(tabId);

		const tabGlobal = Cu.getGlobalForObject(tab.nativeTab);
		if (tabGlobal.gFolderDisplay) {
			// TB < 111
			const msg = this.extension.messageManager.convert(
				tabGlobal.gFolderDisplay.selectedMessage);
			return {
				window: tabGlobal,
				id: msg.id,
			};
		}

		// TB >= 111

		// Get the window of the tab
		let tabWindow;
		if ("chromeBrowser" in tab.nativeTab) {
			// Message is displayed in the mail3PaneTab or a new tab
			tabWindow = tab.nativeTab.chromeBrowser.contentWindow;
		} else {
			// Message is displayed in a new window
			// eslint-disable-next-line no-extra-parens
			tabWindow = /** @type {Window} */ (tab.nativeTab);
		}
		if (!tabWindow) {
			throw new Error("DKIM: tab for msg exists but does not contain a window");
		}

		// Get the inner window that actually shows the message (about:message)
		let msgWindow;
		// eslint-disable-next-line no-extra-parens
		const messageBrowser = /** @type {HTMLIFrameElement} */ (tabWindow.document.getElementById("messageBrowser"));
		if (messageBrowser) {
			// Message is displayed in the mail3PaneTab
			msgWindow = messageBrowser.contentWindow;
			if (!msgWindow) {
				throw new Error("DKIM: messageBrowser exists but does not contain a window");
			}
		} else {
			// Message is displayed in a new window or a new tab
			msgWindow = tabWindow;
		}

		const displayedMessages = ExtensionParent.apiManager.global.getDisplayedMessages(tab);
		let displayedMessage = displayedMessages[0];
		if (!displayedMessage || displayedMessages.length !== 1) {
			return {
				window: msgWindow,
				id: null,
			};
		}
		if (!("id" in displayedMessage)) {
			// TB >= 115
			displayedMessage = this.extension.messageManager.convert(displayedMessage);
		}
		const id = displayedMessage.id;
		return {
			window: msgWindow,
			id,
		};
	}

	/**
	 * Get the Document for a specific message shown in a tab.
	 * Also ensures the DKIM specific elements exist.
	 * Returns null if a different message is shown.
	 *
	 * @param {number} tabId
	 * @param {number} messageId
	 * @returns {Document?}
	 */
	#getAndPrepareDocumentForCurrentMsg(tabId, messageId) {
		const { window, id } = this.#getWindowAndIdOfMsgShownInTab(tabId);

		// Ensure that the tab is still showing the message
		if (id !== messageId) {
			return null;
		}

		this.paint(window);
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
					const document = this.#getAndPrepareDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					const dkimHeaderRow = DkimHeaderRow.getOrThrow(document);
					dkimHeaderRow.show(show);

					return Promise.resolve(true);
				},
				showFromTooltip: (tabId, messageId, show) => {
					const document = this.#getAndPrepareDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					DkimFromAddress.showTooltip(document, show);

					return Promise.resolve(true);
				},
				setDkimHeaderResult: (tabId, messageId, result, warnings, faviconUrl, arh) => {
					const document = this.#getAndPrepareDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					const dkimHeaderField = DKIMHeaderField.getOrThrow(document);
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

					const favicon = DkimFavicon.getOrThrow(document);
					favicon.setFaviconUrl(faviconUrl);

					const resultTooltips = DkimResultTooltip.getAll(document);
					for (const tooltip of resultTooltips) {
						tooltip.value = result;
						tooltip.warnings = warnings;
					}

					return Promise.resolve(true);
				},
				highlightFromAddress: (tabId, messageId, color, backgroundColor) => {
					const document = this.#getAndPrepareDocumentForCurrentMsg(tabId, messageId);
					if (!document) {
						return Promise.resolve(false);
					}

					DkimFromAddress.setHighlightColor(document, color, backgroundColor);

					return Promise.resolve(true);
				},
				reset: (tabId, messageId) => {
					const document = this.#getAndPrepareDocumentForCurrentMsg(tabId, messageId);
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
