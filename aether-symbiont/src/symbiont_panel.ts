import * as vscode from 'vscode';
import { SymbiontLanguageClient } from './lsp_client';
import { readHybridStatus, readSharedSymbiontSettings } from './shared_runtime';

/**
 * WebView panel showing the Meta-Ockham dashboard.
 * Displays: Razor score, twin clusters, abstraction inversions, vault snapshots.
 */
export class SymbiontPanel {
    public static currentPanel: SymbiontPanel | undefined;
    private static readonly VIEW_TYPE = 'aetherSymbiont';

    private readonly _panel: vscode.WebviewPanel;
    private readonly _client: SymbiontLanguageClient;
    private _disposables: vscode.Disposable[] = [];

    private constructor(
        panel: vscode.WebviewPanel,
        client: SymbiontLanguageClient,
        private readonly _repoRoot: string,
    ) {
        this._panel = panel;
        this._client = client;

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._panel.webview.html = this._buildHtml('Lädt…');

        // Handle messages coming from the WebView
        this._panel.webview.onDidReceiveMessage(
            async (msg: { command: string; data?: any }) => {
                switch (msg.command) {
                    case 'razor':
                        await this._handleRazor(msg.data);
                        break;
                    case 'status':
                        await this._handleStatus();
                        break;
                }
            },
            null,
            this._disposables,
        );
    }

    public static createOrShow(extensionUri: vscode.Uri, client: SymbiontLanguageClient, repoRoot: string): void {
        const column = vscode.window.activeTextEditor
            ? vscode.ViewColumn.Beside
            : vscode.ViewColumn.One;

        if (SymbiontPanel.currentPanel) {
            SymbiontPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            SymbiontPanel.VIEW_TYPE,
            'Aether Symbiont',
            column,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            },
        );

        SymbiontPanel.currentPanel = new SymbiontPanel(panel, client, repoRoot);
        // Auto-load server status
        SymbiontPanel.currentPanel._handleStatus().catch(() => {});
    }

    public dispose(): void {
        SymbiontPanel.currentPanel = undefined;
        this._panel.dispose();
        for (const d of this._disposables) d.dispose();
    }

    // ── Private ──────────────────────────────────────────────────────────────

    private async _handleRazor(signals: string[]): Promise<void> {
        try {
            const result = await this._client.sendRequest('aether/razor', { signals }) as any;
            this._panel.webview.postMessage({ type: 'razorResult', data: result });
        } catch (err: any) {
            this._panel.webview.postMessage({ type: 'error', message: String(err) });
        }
    }

    private async _handleStatus(): Promise<void> {
        try {
            const result = await this._client.sendRequest('aether/status', {}) as any;
                        const hybrid = readHybridStatus(this._repoRoot);
                        const shared = readSharedSymbiontSettings(this._repoRoot);
            const html = this._buildHtml(`
                <h2>Server Status</h2>
                <ul>
                  <li>Uptime: ${result.uptime_s}s</li>
                  <li>Requests: ${result.req_count}</li>
                  <li>Vault: ${result.vault_path}</li>
                                    <li>Hybrid Bridge: ${hybrid?.bridge_running ? 'online' : 'offline'}</li>
                                    <li>Hybrid Symbiont: ${hybrid?.symbiont_running ? 'online' : 'offline'}</li>
                                    <li>Shared Socket: ${hybrid?.symbiont_host ?? shared.host}:${hybrid?.symbiont_port ?? shared.port}</li>
                                    <li>Shared Python: ${shared.pythonPath}</li>
                                    <li>Shared Server: ${shared.serverPath}</li>
                </ul>
                <hr/>
                <p>Öffne eine Datei und nutze die Kontextmenü-Befehle
                (<em>Aether: Structural Profile</em>, <em>Apply Ockham Razor</em>) 
                um Ergebnisse hier anzuzeigen.</p>
            `);
            this._panel.webview.html = html;
        } catch {
            this._panel.webview.html = this._buildHtml('<p>Server nicht erreichbar.</p>');
        }
    }

    private _buildHtml(body: string): string {
        return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aether Symbiont</title>
  <style>
    body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
           color: var(--vscode-foreground); background: var(--vscode-editor-background);
           padding: 16px; }
    h1 { font-size: 1.3em; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 6px; }
    h2 { font-size: 1.1em; margin-top: 16px; }
    ul { padding-left: 1.2em; }
    li { margin: 4px 0; }
    code { background: var(--vscode-textBlockQuote-background); padding: 2px 4px; border-radius: 3px; }
    .badge { display: inline-block; background: var(--vscode-badge-background);
             color: var(--vscode-badge-foreground); padding: 1px 6px; border-radius: 10px;
             font-size: 0.85em; margin-left: 6px; }
  </style>
</head>
<body>
  <h1>Aether Symbiont <span class="badge">Meta-Ockham</span></h1>
  ${body}
  <script>
    const vscode = acquireVsCodeApi();
    window.addEventListener('message', event => {
      const msg = event.data;
      if (msg.type === 'razorResult') {
        document.body.innerHTML += '<pre>' + JSON.stringify(msg.data, null, 2) + '</pre>';
      }
    });
  </script>
</body>
</html>`;
    }
}
