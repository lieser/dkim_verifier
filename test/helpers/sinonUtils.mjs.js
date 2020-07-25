/**
 * Helper to get global sinon with type information.
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/** @type {import("sinon")} */
// @ts-expect-error
const sinon = globalThis.sinon;
export default sinon;
