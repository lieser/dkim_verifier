/**
 * Copyright (c) 2013-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

/**
 * DKIM signature error (PERMFAIL).
 */
export class DKIM_SigError extends Error {
	/**
	 * DKIM signature error (PERMFAIL).
	 *
	 * @param {string} errorType
	 * @param {any[]} [errorStrParams]
	 */
	constructor(errorType, errorStrParams = []) {
		super(errorType);
		this.name = this.constructor.name;
		this.errorType = errorType;
		this.errorStrParams = errorStrParams;
		// @ts-expect-error
		this.stack = this.stack.substring(this.stack.indexOf("\n") + 1);
	}
}

/**
 * Temporary DKIM signature error (TEMPFAIL).
 */
export class DKIM_TempError extends Error {
	/**
	 * Temporary DKIM signature error (PERMFAIL).
	 *
	 * @param {string} errorType
	 * @param {any[]} [errorStrParams]
	 */
	constructor(errorType, errorStrParams = []) {
		super(errorType);
		this.name = this.constructor.name;
		this.errorType = errorType;
		this.errorStrParams = errorStrParams;
		// @ts-expect-error
		this.stack = this.stack.substring(this.stack.indexOf("\n") + 1);
	}
}

/**
 * General error.
 */
export class DKIM_Error extends Error {
	/**
	 * General error.
	 *
	 * @param {string} [message]
	 */
	constructor(message) {
		super(message);
		this.name = this.constructor.name;
		// @ts-expect-error
		this.stack = this.stack.substring(this.stack.indexOf("\n") + 1);
	}
}
