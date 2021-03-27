/**
 * Copyright (c) 2013-2019 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

/**
 * DKIM signature error.
 */
export class DKIM_SigError extends Error {
	/**
	 * DKIM signature error.
	 *
	 * @constructor
	 *
	 * @param {String} errorType
	 * @param {any[]} [errorStrParams]
	 */
	constructor(errorType, errorStrParams = []) {
		// super(tryGetFormattedString(dkimStrings, errorType, errorStrParams) ||
		// 	errorType ||
		// 	dkimStrings.getString("DKIM_SIGERROR_DEFAULT"));
		// this.name = dkimStrings.getString("DKIM_SIGERROR") + " (" + errorType + ")";
		super(errorType);
		this.name = "DKIM_SigError";
		this.errorType = errorType;
		this.errorStrParams = errorStrParams;
		this.stack = this.stack.substring(this.stack.indexOf('\n')+1);
	}
}

/**
 * DKIM internal error
 */
export class DKIM_InternalError extends Error {
	/**
	 * DKIM internal error
	 *
	 * @constructor
	 *
	 * @param {String|null} [message]
	 * @param {String} [errorType]
	 */
	constructor(message, errorType) {
		// super(message ||
		// 	tryGetString(dkimStrings, errorType) ||
		// 	errorType ||
		// 	dkimStrings.getString("DKIM_INTERNALERROR_DEFAULT"));
		// this.name = dkimStrings.getString("DKIM_INTERNALERROR") + " (" + errorType + ")";
		super(errorType);
		this.name = "DKIM_InternalError";
		this.errorType = errorType;
		this.stack = this.stack.substring(this.stack.indexOf('\n')+1);
	}
}
