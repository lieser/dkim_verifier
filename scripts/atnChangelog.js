/**
 * Create Version Notes for ATN for the latest release.
 */

// @ts-check

import fs from "node:fs/promises";
import { marked } from "marked";

const changelog = await fs.readFile("CHANGELOG.md", { encoding: "utf8" });
const parts = changelog.split(/^## .+$/m);

/** @type {import("marked").Renderer} */
// @ts-expect-error
const renderer = {
	heading({ tokens }) {
		const text = this.parser.parseInline(tokens);
		return `<strong>${text}</strong>\n`;
	},
};
marked.use({ renderer });

const parsed = marked.parse(parts[1] ?? "");
console.log(parsed);
