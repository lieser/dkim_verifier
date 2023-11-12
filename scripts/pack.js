/**
 * Pack the extension into a xpi/zip file.
 */

// @ts-check

import JSZip from "jszip";
import chalk from "chalk";
import fs from "node:fs/promises";
import { globby } from "globby";
import { simpleGit } from "simple-git";

/**
 * Get the date as a string in the form of `YYYY-MM-DD`
 *
 * @param {Date} date
 * @returns {string}
 */
function dateToString(date) {
	return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

/**
 * Collect all files that should be included in the packed extension.
 *
 * @returns {Promise<string[]>}
 */
async function collectFiles() {
	/** @type {string[]} */
	const files = [];

	files.push(...await globby("chrome", {
		expandDirectories: {
			extensions: [
				// content
				"js", "xml", "xul",
				// locale
				"dtd", "properties",
				// skin
				"css", "png",
			],
		}
	}));
	files.push(...await globby("components", {
		expandDirectories: {
			extensions: ["js"],
		}
	}));
	files.push(...await globby("data", { expandDirectories: true }));
	files.push(...await globby("defaults", {
		expandDirectories: {
			extensions: ["js"],
		}
	}));
	files.push(...await globby("modules", {
		expandDirectories: {
			extensions: ["js"],
		}
	}));
	files.push(...await globby("thirdparty", { expandDirectories: true }));

	files.push("CHANGELOG.md");
	files.push("chrome.manifest");
	files.push("icon.png");
	files.push("icon_32.png");
	files.push("install.rdf");
	files.push("LICENSE.txt");
	files.push("README.md");
	files.push("THIRDPARTY_LICENSE.txt");

	return files;
}

/**
 * Check if the build is dirty.
 *
 * @param {string[]} files
 * @returns {Promise<boolean>}
 */
async function isDirty(files) {
	const status = await simpleGit().status(["--ignored"]);
	let dirty = false;

	const modifiedFiles = status.modified.filter(value => files.includes(value));
	if (modifiedFiles.length !== 0) {
		dirty = true;
		console.warn(chalk.red("Dirty build: some files are modified!"));
		console.log("Included modified files:", modifiedFiles);
	}

	const addedFiles = status.not_added.filter(value => files.includes(value));
	if (addedFiles.length !== 0) {
		dirty = true;
		console.warn(chalk.red("Dirty build: some untracked files are included!"));
		console.log("Included untracked files:", addedFiles);
	}

	const stagedFiles = status.staged.filter(value => files.includes(value));
	if (stagedFiles.length !== 0) {
		dirty = true;
		console.warn(chalk.red("Dirty build: some files are staged!"));
		console.log("Included staged files:", stagedFiles);
	}

	const ignoredFiles = status.ignored?.filter(value => files.includes(value));
	if (ignoredFiles && ignoredFiles.length !== 0) {
		dirty = true;
		console.warn(chalk.red("Dirty build: some ignored files are included!"));
		console.log("Included ignored files:", ignoredFiles);
	}

	return dirty;
}

/**
 * Get the archive name and date that should be used.
 *
 * @param {boolean} dirty
 * @returns {Promise<[string, Date]>}
 */
async function createArchiveInfo(dirty) {
	if (dirty) {
		return ["dkim_verifier@pl.xpi", new Date()];
	}

	const changelog = await fs.readFile("CHANGELOG.md", { encoding: "utf8" });

	if (changelog.includes("\n## Unreleased")) {
		const commit = await simpleGit().log({ maxCount: 1 });
		const date = new Date(commit.latest?.date ?? new Date());
		const ShortHashLength = 7;
		const shortHash = commit.latest?.hash.substring(0, ShortHashLength);
		return [`dkim_verifier@pl-${dateToString(date)}-${shortHash}.xpi`, date];
	}

	let matchRes = changelog.match(/## (\S+) \((\S+)\)/);
	if (!matchRes) {
		throw new Error("Can not parse changelog");
	}
	const [, changelogVersion, date] = matchRes;
	if (!changelogVersion || !date) {
		throw new Error("Can not parse changelog");
	}
	const installRdf = await fs.readFile("install.rdf", "utf8");
	matchRes = installRdf.match(/<em:version>(2.2.1)<\/em:version>/);
	if (!matchRes) {
		throw new Error("Can not parse install.rdf");
	}
	const [, installRdfVersion] = matchRes;
	if (changelogVersion !== installRdfVersion) {
		throw new Error("Version in changelog doe not match manifest");
	}
	return [`dkim_verifier-${changelogVersion}.xpi`, new Date(date)];

}

/**
 * Try to remove/rename old build.
 * In Windows Thunderbird keeps a reference to an installed xpi,
 * which results in errors if we try to remove it.
 *
 * @param {string} name
 * @returns {Promise<void>}
 */
async function removeOldBuild(name) {
	const inUseName = "dkim_verifier_in_use@pl.xpi";

	try {
		await fs.rm(inUseName, { force: true });
	} catch (error) {
		// ignore
	}

	try {
		await fs.rm(name, { force: true });
	} catch (error) {
		// Sometimes if removing does not work, renaming does
		fs.rename(name, inUseName);
		await fs.rm(name, { force: true });
	}
}

/**
 * Pack the given files into a ZIP archive.
 *
 * @param {string[]} files
 * @param {string} archiveName
 * @param {Date} archiveDate
 * @returns {Promise<void>}
 */
async function packFiles(files, archiveName, archiveDate) {
	/**
	 * Add a single file to a ZIP archive.
	 *
	 * @param {JSZip} zip
	 * @param {string} filePath
	 * @returns {void}
	 */
	function addFile(zip, filePath) {
		zip.file(filePath, fs.readFile(filePath), {
			date: archiveDate,
			createFolders: false,
		});
	}

	// Sort files to get deterministic output
	files.sort();

	const zip = new JSZip();
	files.forEach(file => addFile(zip, file));

	fs.writeFile(archiveName, await zip.generateAsync({
		type: "nodebuffer",
		compression: "DEFLATE",
	}));
}

const packedFiles = await collectFiles();
const dirty = await isDirty(packedFiles);
const [archiveName, archiveDate] = await createArchiveInfo(dirty);
await removeOldBuild(archiveName);
await packFiles(packedFiles, archiveName, archiveDate);
console.info(`Created packed extension '${archiveName}'`);
