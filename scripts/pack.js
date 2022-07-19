/**
 * Pack the extension into a xpi/zip file.
 */

// @ts-check

import JSZip from "jszip";
import chalk from "chalk";
import { dateToString } from "../modules/utils.mjs.js";
import fs from "node:fs/promises";
import { globby } from "globby";
import { simpleGit } from "simple-git";

/**
 * Collect all files that should be included in the packed extension.
 *
 * @returns {Promise<string[]>}
 */
async function collectFiles() {
	/** @type {string[]} */
	const files = [];

	files.push(...await globby("_locales", {
		expandDirectories: {
			extensions: ["json"],
		}
	}));
	files.push(...await globby("content", {
		expandDirectories: {
			extensions: ["html", "css", "js"],
		}
	}));
	files.push(...await globby("data", { expandDirectories: true }));
	files.push(...await globby("experiments", {
		expandDirectories: {
			extensions: ["js", "json"],
		}
	}));
	files.push(...await globby("modules", {
		expandDirectories: {
			extensions: ["js"],
		}
	}));
	files.push(...await globby("thirdparty", { expandDirectories: true }));

	files.push("CHANGELOG.md");
	files.push("icon.svg");
	files.push("LICENSE.txt");
	files.push("manifest.json");
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

	const res = changelog.match(/## (\S+) \((\S+)\)/);
	if (!res) {
		throw new Error("Can not parse changelog");
	}
	const [, version, date] = res;
	if (!version || !date) {
		throw new Error("Can not parse changelog");
	}
	const manifest = JSON.parse(await fs.readFile("manifest.json", "utf8"));
	if (version !== manifest.version) {
		throw new Error("Version in changelog doe not match manifest");
	}
	return [`dkim_verifier-${version}.xpi`, new Date(date)];

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
