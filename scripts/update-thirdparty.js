/**
 * Update the included third party dependencies to the current ones in node_modules.
 */

// @ts-check

import * as fs from "node:fs/promises";

await fs.mkdir("thirdparty/tweetnacl-es6", {recursive: true});
await fs.copyFile("node_modules/tweetnacl-es6/LICENSE", "thirdparty/tweetnacl-es6/LICENSE");
await fs.copyFile("node_modules/tweetnacl-es6/AUTHORS.md", "thirdparty/tweetnacl-es6/AUTHORS.md");
await fs.copyFile("node_modules/tweetnacl-es6/nacl-fast-es.js", "thirdparty/tweetnacl-es6/nacl-fast-es.js");
