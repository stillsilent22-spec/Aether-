import * as path from 'path';
import * as vscode from 'vscode';
import { SymbiontLanguageClient } from './lsp_client';
import { SymbiontPanel } from './symbiont_panel';
import { DeltaStatusBar } from './delta_status';
import {
    readHybridStatus,
    readSharedSymbiontSettings,
    repoRootFromExtension,
    writeVscodeRuntimeStatus,
} from './shared_runtime';

let client: SymbiontLanguageClient | undefined;
let statusBar: DeltaStatusBar | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    const config = vscode.workspace.getConfiguration('aether');
    const repoRoot = repoRootFromExtension(context.extensionPath);
    const shared = readSharedSymbiontSettings(repoRoot);

    // ── Server-Pfad auflösen ──────────────────────────────────────────────
    let serverPath = config.get<string>('serverPath', '');
    if (!serverPath) {
        serverPath = path.join(repoRoot, shared.serverPath);
    }
    const pythonPath = config.get<string>('pythonPath', '') || shared.pythonPath;

    // ── LSP-Client starten ────────────────────────────────────────────────
    const hybridAtStart = readHybridStatus(repoRoot);
    const useSharedSocket = Boolean(hybridAtStart?.symbiont_running && hybridAtStart?.symbiont_host && hybridAtStart?.symbiont_port);
    client = new SymbiontLanguageClient(
        serverPath,
        pythonPath,
        useSharedSocket ? hybridAtStart?.symbiont_host : undefined,
        useSharedSocket ? hybridAtStart?.symbiont_port : undefined,
    );
    let lastError = '';
    try {
        await client.start();
    } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        writeVscodeRuntimeStatus(repoRoot, {
            active: false,
            pythonPath,
            serverPath,
            reqMode: 'spawn',
            sharedSettings: true,
            lastError,
            updatedAt: new Date().toISOString(),
        });
        throw err;
    }

    const hybrid = readHybridStatus(repoRoot);
    writeVscodeRuntimeStatus(repoRoot, {
        active: true,
        pythonPath,
        serverPath,
        reqMode: useSharedSocket ? 'shared-socket' : 'spawn',
        sharedSettings: true,
        lastError,
        updatedAt: new Date().toISOString(),
    });

    // ── Status-Bar ────────────────────────────────────────────────────────
    statusBar = new DeltaStatusBar(client, repoRoot);
    context.subscriptions.push(statusBar);

    // ── Befehle registrieren ──────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('aether.profile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const text = editor.document.getText(editor.selection) || editor.document.getText();
            const result = await client!.sendRequest('aether/profile', { signal: text });
            vscode.window.showInformationMessage(
                `[Aether] Entropy=${(result as any).entropy?.toFixed(3)} | ` +
                `Tokens=${(result as any).token_count} | ` +
                `Type=${(result as any).signal_type}`
            );
        }),

        vscode.commands.registerCommand('aether.razor', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const doc = editor.document;
            // Split by paragraph-breaks as multiple signals
            const signals = doc.getText().split(/\n{2,}/).filter(s => s.trim().length > 0);
            const result = await client!.sendRequest('aether/razor', { signals });
            const report = result as any;
            const msg = [
                `[Aether Razor] ${report.scores?.length ?? 0} Signale`,
                `Twins: ${report.twin_clusters?.length ?? 0}`,
                `Inversions: ${report.abstraction_inversions?.length ?? 0}`,
                `Confidence: ${report.confidence?.toFixed(3)}`,
            ].join(' | ');
            vscode.window.showInformationMessage(msg);
            statusBar?.update(report.confidence ?? 0);
        }),

        vscode.commands.registerCommand('aether.snapshot', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const text = editor.document.getText(editor.selection) || editor.document.getText();
            const result = await client!.sendRequest('aether/snapshot', { signal: text });
            const h = result as any;
            vscode.window.showInformationMessage(
                `[Aether] Snapshot gespeichert: ${h.snapshot_id?.slice(0, 8)}…`
            );
        }),

        vscode.commands.registerCommand('aether.twins', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const signals = editor.document.getText().split(/\n{2,}/).filter(s => s.trim().length > 0);
            const result = await client!.sendRequest('aether/twins', { signals });
            const r = result as any;
            if ((r.clusters?.length ?? 0) === 0) {
                vscode.window.showInformationMessage('[Aether] Keine Zwillinge gefunden.');
            } else {
                vscode.window.showInformationMessage(
                    `[Aether] ${r.clusters.length} Twin-Cluster gefunden!`
                );
            }
        }),

        vscode.commands.registerCommand('aether.showPanel', () => {
            SymbiontPanel.createOrShow(context.extensionUri, client!, repoRoot);
        }),
    );

    // ── Initiale Status-Bar-Aktualisierung ────────────────────────────────
    setTimeout(() => statusBar?.refresh(), 2000);
}

export async function deactivate(): Promise<void> {
    const extensionPath = vscode.extensions.getExtension('aether.aether-symbiont')?.extensionPath;
    if (extensionPath) {
        writeVscodeRuntimeStatus(repoRootFromExtension(extensionPath), {
            active: false,
            pythonPath: '',
            serverPath: '',
            reqMode: 'stopped',
            sharedSettings: true,
            lastError: '',
            updatedAt: new Date().toISOString(),
        });
    }
    await client?.stop();
}
