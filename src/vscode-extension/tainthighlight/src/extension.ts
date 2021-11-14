// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { readFile } from 'fs';
import * as path from 'path';
import { assert } from 'console';

var is_active = true;
// filename -> [taintedRanges, untaintedRanges]
var taintsPerFile = new Map<string, [vscode.DecorationOptions[], vscode.Range[]]>();

function parseRange(startLine: number, startColumn: number, endLine: number, endColumn: number): vscode.Range {
	return new vscode.Range(
		new vscode.Position(startLine - 1, startColumn - 1), new vscode.Position(endLine - 1, endColumn)
	);
}

function flagIsTainted(flags: string) {
	if (flags === "000000") {return true;}
	flags = flags.replace("0", "").replace("B", "b");
	// if there are only lowercase flags, the line is not tainted
	return flags !== flags.toLowerCase();
}

/*
C=cmp
B=branch
O=offset
P=pointer
D=destination
S=source
L=length
*/

function expandFlag(flags: string) {
	let res:string[] = [];
	for (let c of flags) {
		if (c === "0" || c === c.toLowerCase()) {
			continue;
		}
		switch (c) {
			case 'C':
				res.push("cmp");
				break;
			case 'B': // B in case of branches is only for taken/non taken
			// 	res.push("branch");
				break;
			case 'O':
				res.push("offset");
				break;
			case 'P':
				res.push("ptr");
				break;
			case 'D':
				res.push("dst");
				break;
			case 'S':
				res.push("src");
				break;
			case 'L':
				res.push("len");
				break;
			case 'T':
				res.push("taint");
				break;
			case 'V':
				res.push("value");
				break;
			default:
				res.push("unknown " + c);
				break;
		}
	}
	return res.join(', ');
}

function parseFile(decorationTainted: vscode.TextEditorDecorationType, decorationNonTainted: vscode.TextEditorDecorationType) {
	const editor = vscode.window.activeTextEditor;
	if (editor === undefined) {
		vscode.window.showErrorMessage("No file opened");
		return;
	}
	const fileName = editor.document.fileName;
	const baseFileName = path.basename(fileName);
	// manage different filename extensions
	// -> even no extension and dot in directory
	const taintFileName = path.join(path.dirname(fileName), path.basename(fileName, path.extname(fileName)) + '.taint');
	// vscode.window.showInformationMessage(baseFileName.toString());
	const taintedRanges: vscode.DecorationOptions[] = [];
	const nonTaintedRanges: vscode.Range[] = [];
	const taintedLines = new Map<number, Map<number, string>>(); // line -> {columns -> taint_string}
	const nonTaintedLines = new Set<number>();
	if (!is_active) {
		editor.setDecorations(decorationTainted, taintedRanges);
		editor.setDecorations(decorationNonTainted, nonTaintedRanges);
		return;
	}
	const ranges = taintsPerFile.get(baseFileName);
	if (ranges !== undefined) {
		const taintedRanges: vscode.DecorationOptions[] = ranges[0];
		const nonTaintedRanges: vscode.Range[] = ranges[1];
		editor.setDecorations(decorationTainted, taintedRanges);
		editor.setDecorations(decorationNonTainted, nonTaintedRanges);
		// vscode.window.showInformationMessage("Loading from cache");
		return;
	}
	// vscode.window.showInformationMessage("Parsing taint file");
	readFile(taintFileName, (err, data) => {
		if (err) {
			return; 
		}
		data.toString().split('\n').forEach(function(line:string) {
			if (!line.includes(baseFileName)) { return; }
			// console.log(line);
			let instr = line.split(':')[0].trim();
			let flags = line.split(':')[1];
			let sourceInfo = line.split(baseFileName + ':')[1];
			let lineNum = parseInt(sourceInfo.split(':')[0]);
			let columnNum = parseInt(sourceInfo.split(':')[1]);
			if (lineNum === 0) {return;}

			// line is tainted if has at least a tainted part
			if (flagIsTainted(flags)) {
				if (!taintedLines.has(lineNum)) {
					taintedLines.set(lineNum, new Map<number,string>());
				}
				const taint_string = taintedLines.get(lineNum)?.get(columnNum);
				const new_taint = '**' + instr + '**: ' + expandFlag(flags);
				if (taint_string === undefined) {
					taintedLines.get(lineNum)?.set(columnNum, new_taint);
				} else {
					taintedLines.get(lineNum)?.set(columnNum, taint_string + '  \n' + new_taint);
				}
				nonTaintedLines.delete(lineNum);
			} else if (!taintedLines.has(lineNum)) {
				nonTaintedLines.add(lineNum);
			}
		});
		taintedLines.forEach(function(columns:Map<number,string>, lineNum:number) {
			columns.forEach(function(taint_str:string, column:number) {
				const position = editor.document.getWordRangeAtPosition(
					new vscode.Position(lineNum-1, column-1));
				const symbol_position = editor.document.getWordRangeAtPosition(
					new vscode.Position(lineNum-1, column-1), 
					/[-!%^&*()_+|~=:<>?\/]+/);
				const default_range = parseRange(lineNum, column, lineNum, column);
				let range = default_range;
				taintedRanges.push({range: range, hoverMessage: new vscode.MarkdownString(taint_str)});
			});
		});
		nonTaintedLines.forEach(function(lineNum:number) {
			nonTaintedRanges.push(parseRange(lineNum, 1, lineNum, 2));
		});
		editor.setDecorations(decorationTainted, taintedRanges);
		editor.setDecorations(decorationNonTainted, nonTaintedRanges);
		taintsPerFile.set(baseFileName, [taintedRanges, nonTaintedRanges]);
	});
}

function parseTaintFile() {
	const editor = vscode.window.activeTextEditor;
	if (editor === undefined) {
		vscode.window.showErrorMessage("No file opened");
		return;
	}
	const fileName = editor.document.fileName;
	const baseFileName = path.basename(fileName);
	if (!baseFileName.includes('.taint')) {
		vscode.window.showErrorMessage("Not a .taint file");
		return;
	}
	// const taintedLines = new Map<number, Map<number, string>>(); // line -> {columns -> taint_string}
	// const nonTaintedLines = new Set<number>();
	const linesCache = new Map<string, [Map<number, Map<number, string>>, Set<number>]>();;
	// vscode.window.showInformationMessage("Parsing taint file");
	readFile(fileName, (err, data) => {
		if (err) {
			vscode.window.showErrorMessage("Error opening file");
			return; 
		}

		data.toString().split('\n').forEach(function(line:string) {
			// console.log(line);
			if (!line.includes('\t')) { return; }
			let instr = line.split(':')[0].trim();
			let flags = line.split(':')[1];
			let currFileName = line.split('\t')[1].split(':')[0];
			// console.log(currFileName);
			if (currFileName === undefined || currFileName === '') {return;}
			let sourceInfo = line.split(currFileName + ':')[1];
			let lineNum = parseInt(sourceInfo.split(':')[0]);
			let columnNum = parseInt(sourceInfo.split(':')[1]);
			if (lineNum === 0) {return;}

			let taintedLines : Map<number, Map<number, string>>; // line -> {columns -> taint_string}
			let nonTaintedLines : Set<number>;
			let cachedLines = linesCache.get(currFileName);
			if (cachedLines === undefined) {
				taintedLines = new Map<number, Map<number, string>>(); // line -> {columns -> taint_string}
				nonTaintedLines = new Set<number>();
			} else {
				taintedLines = cachedLines[0];
				nonTaintedLines = cachedLines[1];
			}

			// add if it was not present
			if (cachedLines === undefined) {
				linesCache.set(currFileName, [taintedLines, nonTaintedLines]);
			}

			// line is tainted if has at least a tainted part
			if (flagIsTainted(flags)) {
				if (!taintedLines.has(lineNum)) {
					taintedLines.set(lineNum, new Map<number,string>());
				}
				const taint_string = taintedLines.get(lineNum)?.get(columnNum);
				const new_taint = '**' + instr + '**: ' + expandFlag(flags);
				if (taint_string === undefined) {
					taintedLines.get(lineNum)?.set(columnNum, new_taint);
				} else {
					taintedLines.get(lineNum)?.set(columnNum, taint_string + '  \n' + new_taint);
				}
				nonTaintedLines.delete(lineNum);
			} else if (!taintedLines.has(lineNum)) {
				nonTaintedLines.add(lineNum);
			}
		});

		// for each cached file taint information, transform in a Range and cache that
		for (let [aFileName, cachedLines] of linesCache.entries()) {
			let taintedLines = cachedLines[0];
			let nonTaintedLines = cachedLines[1];
			// console.log("Saving taint info for " + aFileName);
			let taintedRanges: vscode.DecorationOptions[];
			let nonTaintedRanges: vscode.Range[];
			const ranges = taintsPerFile.get(aFileName);
			if (ranges !== undefined) {
				taintedRanges = ranges[0];
				nonTaintedRanges = ranges[1];
			} else {
				taintedRanges = [];
				nonTaintedRanges = [];
			}
			taintedLines.forEach(function(columns:Map<number,string>, lineNum:number) {
				columns.forEach(function(taint_str:string, column:number) {
					const position = editor.document.getWordRangeAtPosition(
						new vscode.Position(lineNum-1, column-1));
					const symbol_position = editor.document.getWordRangeAtPosition(
						new vscode.Position(lineNum-1, column-1), 
						/[-!%^&*()_+|~=:<>?\/]+/);
					const default_range = parseRange(lineNum, column, lineNum, column);
					let range = default_range;
					taintedRanges.push({range: range, hoverMessage: new vscode.MarkdownString(taint_str)});
				});
			});
			nonTaintedLines.forEach(function(lineNum:number) {
				nonTaintedRanges.push(parseRange(lineNum, 1, lineNum, 2));
			});
			// add if it was not present
			if (ranges === undefined) {
				taintsPerFile.set(aFileName, [taintedRanges, nonTaintedRanges]);
			}
		}
		vscode.window.showInformationMessage("Saved taint info for " + [...linesCache.keys()].join(', '));
	});
}

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export async function activate(context: vscode.ExtensionContext) {

	const decorationTainted = vscode.window.createTextEditorDecorationType({
		backgroundColor: 'rgba(212, 175, 55, 0.3)',
		isWholeLine: false,
		overviewRulerColor: 'rgba(212, 175, 55, 0.8)'
	});
	const decorationNonTainted = vscode.window.createTextEditorDecorationType({
		backgroundColor: 'rgba(0, 255, 0, 0.08)',
		isWholeLine: true,
		overviewRulerColor: 'rgba(0, 255, 0, 0.3)'
	});

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	let disposable = vscode.commands.registerCommand('extension.highlightTainted', () => {
		// The code you place here will be executed every time your command is executed
		is_active = true;
		parseFile(decorationTainted, decorationNonTainted);
	});

	let disposable_disable = vscode.commands.registerCommand('extension.disableHighlightTainted', () => {
		is_active = false;
		parseFile(decorationTainted, decorationNonTainted);
	});

	let disposable_master = vscode.commands.registerCommand('extension.parseTaintFile', () => {
		parseTaintFile();
	});

	vscode.window.onDidChangeActiveTextEditor(() => {
		var activeTextEditor = vscode.window.activeTextEditor;
		if (activeTextEditor === undefined) {
			return;
		}
		parseFile(decorationTainted, decorationNonTainted);
	});

	context.subscriptions.push(disposable);
	context.subscriptions.push(disposable_master);
	context.subscriptions.push(disposable_disable);
}

// this method is called when your extension is deactivated
export function deactivate() {}
