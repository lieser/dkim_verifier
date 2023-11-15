/**
 * Update the included third party dependencies to the current ones in node_modules.
 */

// @ts-check

import * as fs from "node:fs/promises";

/**
 * Append information about an npm package to the readme.
 *
 * @param {{packages: {[x: string]: {version: string, resolved: string}}}} packageLock
 * @param {string} packageName
 */
async function writePackageInfo(packageLock, packageName) {
	const packageInfo = packageLock.packages[`node_modules/${packageName}`];
	if (!packageInfo) {
		throw new Error(`Could not find package '${packageName}`);
	}
	const readme =
		`\n## ${packageName}\n\n` +
		`- Name: ${packageName}\n` +
		"- Source: npm\n" +
		`- Version: ${packageInfo.version}\n` +
		`- Download URL: <${packageInfo.resolved}>\n`;
	await fs.appendFile("thirdparty/README.md", readme);
}

const packageLock = JSON.parse(await fs.readFile("package-lock.json", "utf8"));
const readme = `# Third-party libraries

Unchanged third-party libraries included in the add-on.

See [THIRDPARTY_LICENSE.txt](../THIRDPARTY_LICENSE.txt) in the root directory for licensing information.

This file contains the information which versions of the third-party libraries are included.
`;

await fs.rm("thirdparty", { recursive: true, force: true });
await fs.mkdir("thirdparty");
await fs.writeFile("thirdparty/README.md", readme);

await fs.mkdir("thirdparty/tweetnacl-es6");
await fs.copyFile("node_modules/tweetnacl-es6/LICENSE", "thirdparty/tweetnacl-es6/LICENSE");
await fs.copyFile("node_modules/tweetnacl-es6/AUTHORS.md", "thirdparty/tweetnacl-es6/AUTHORS.md");
await fs.copyFile("node_modules/tweetnacl-es6/nacl-fast-es.js", "thirdparty/tweetnacl-es6/nacl-fast-es.js");
await writePackageInfo(packageLock, "tweetnacl-es6");
