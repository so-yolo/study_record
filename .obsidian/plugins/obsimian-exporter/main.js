/*
THIS IS A GENERATED FILE BUNDLED BY ROLLUP.
If you want to view the source, visit the package's GitHub repository.
*/

'use strict';

var obsidian = require('obsidian');

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function pick(obj, keys) {
    const out = {};
    keys.forEach((k) => (out[k] = obj[k]));
    return out;
}
function fromPairs(pairs) {
    const out = {};
    for (let i = 0; i < (pairs === null || pairs === void 0 ? void 0 : pairs.length); i++) {
        out[pairs[i][0]] = pairs[i][1];
    }
    return out;
}
function zipObject(props, values) {
    const out = {};
    for (let i = 0; i < props.length; i++) {
        out[props[i]] = values[i];
    }
    return out;
}

const TFolderProps = ["path", "name"];
const TFileProps = TFolderProps.concat("stat", "basename", "extension");
function TFileToObsimianFile(f) {
    return Object.assign(Object.assign({}, pick(f, TFileProps)), { parent: TFolderToObsimianFolder(f.parent) });
}
function TFolderToObsimianFolder(f) {
    if (!f) {
        return null;
    }
    return Object.assign(Object.assign({}, pick(f, TFolderProps)), { parent: TFolderToObsimianFolder(f.parent) });
}

/**
 * Dumps the output of Obsidian's APIs into {@code outFile} for testing.
 */
function exportData(plugin, outFile) {
    return __awaiter(this, void 0, void 0, function* () {
        const data = yield gatherMarkdownData(plugin.app);
        yield writeData(plugin, data, outFile);
        return data;
    });
}
function gatherMarkdownData(app) {
    return __awaiter(this, void 0, void 0, function* () {
        const files = app.vault.getMarkdownFiles();
        const paths = files.map((f) => f.path);
        const markdownContents = yield Promise.all(files.map((md) => app.vault.read(md)));
        const metadatas = files.map((md) => app.metadataCache.getFileCache(md));
        const getDest = (link, path) => TFileToObsimianFile(app.metadataCache.getFirstLinkpathDest(link, path));
        const fileLinkpathDests = files.map((md, i) => { var _a; return fromPairs((_a = metadatas[i].links) === null || _a === void 0 ? void 0 : _a.map((l) => [l.link, getDest(l.link, md.path)])); });
        return {
            "vault.getMarkdownFiles()": files.map(TFileToObsimianFile),
            "vault.read(*)": zipObject(paths, markdownContents),
            "metadataCache.getCache(*)": zipObject(paths, metadatas),
            "metadataCache.getFirstLinkpathDest(*)": zipObject(paths, fileLinkpathDests),
        };
    });
}
function writeData(plugin, data, outFile) {
    return __awaiter(this, void 0, void 0, function* () {
        return plugin.app.vault.create(outFile, JSON.stringify(data, null, 2));
    });
}

/** A plugin settings tab for Obsimian settings. */
class ObsimianExportPluginSettingsTab extends obsidian.PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }
    /** Returns an {@code onChange} function that saves the new value to settings. */
    onChangeSave(name) {
        return (value) => __awaiter(this, void 0, void 0, function* () {
            this.plugin.settings[name] = value;
            this.plugin.saveData(this.plugin.settings);
        });
    }
    /** Renders the settings page. */
    display() {
        let { containerEl } = this;
        containerEl.empty();
        new obsidian.Setting(containerEl)
            .setName("Export directory")
            .setDesc("The directory to write export data into. Relative paths are resolved relative to the vault directory.")
            .addText((text) => {
            text.inputEl.style.width = "100%";
            text
                .setPlaceholder("/path/to/export/directory")
                .setValue(this.plugin.settings.outDir)
                .onChange(this.onChangeSave("outDir"));
        });
    }
}

const DEFAULT_SETTINGS = {
    outDir: ".",
};
/** Provides an "Export data" command to dump an Obsimian-compatible data file. */
class ObsimianExportPlugin extends obsidian.Plugin {
    onload() {
        return __awaiter(this, void 0, void 0, function* () {
            console.log("loading ObsimianExportPlugin");
            yield this.loadSettings();
            this.addCommand({
                id: "obsimian-export-data",
                name: "Export data for testing",
                callback: () => {
                    const outPath = `${this.settings.outDir}/${this.app.vault.getName() + ".json"}`;
                    exportData(this, outPath);
                },
            });
            this.addSettingTab(new ObsimianExportPluginSettingsTab(this.app, this));
        });
    }
    loadSettings() {
        return __awaiter(this, void 0, void 0, function* () {
            this.settings = Object.assign(Object.assign({}, DEFAULT_SETTINGS), (yield this.loadData()));
        });
    }
}

module.exports = ObsimianExportPlugin;


/* nosourcemap */