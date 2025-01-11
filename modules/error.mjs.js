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
 *
 * User visible errors that occur during DKIM signature verification,
 * that are considered permanent failures.
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
 *
 * User visible errors that are considered temporary failures.
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
 *
 * Errors that are not directly shown to the user,
 * but are still expected to potentially occur if bad input is given.
 *
 *
 * Errors that should normally not occur, and indicate a programming error,
 * are thrown as the builtin Error type.
 *
 * Note that for simplicity, in experiments only Error is used.
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
