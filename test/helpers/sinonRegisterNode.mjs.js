/**
 * Helper to load sinon globally in Node.
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

import sinon from "sinon";
// @ts-expect-error
globalThis.sinon = sinon;
