import * as vscode from 'vscode';
import { SymbiontLanguageClient } from './lsp_client';
import { readHybridStatus } from './shared_runtime';

/**
 * Status bar integration — shows live Ockham score in the VS Code status bar.
 * Refreshes every 30s in the background.
 */
export class DeltaStatusBar implements vscode.Disposable {
    private readonly _item: vscode.StatusBarItem;
    private _timer: ReturnType<typeof setInterval> | null = null;
    private readonly _repoRoot: string;

    constructor(private readonly _client: SymbiontLanguageClient, repoRoot: string) {
        this._repoRoot = repoRoot;
        this._item = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            200,
        );
        this._item.command = 'aether.showPanel';
        this._item.tooltip = 'Aether Symbiont — klicken für Dashboard';
        this._item.text = '$(symbol-misc) Aether';
        this._item.show();

        // Refresh every 30s
        this._timer = setInterval(() => this.refresh(), 30_000);
    }

    public update(confidence: number): void {
        const icon = confidence >= 0.7 ? '$(check)' : confidence >= 0.4 ? '$(warning)' : '$(error)';
        this._item.text = `${icon} Razor: ${confidence.toFixed(2)}`;
    }

    public async refresh(): Promise<void> {
        try {
            const result = await this._client.sendRequest('aether/status', {}) as any;
            const uptime = Math.round(result.uptime_s ?? 0);
            const hybrid = readHybridStatus(this._repoRoot);
            const hybridBadge = hybrid?.symbiont_running ? 'hybrid' : 'local';
            this._item.text = `$(symbol-misc) Aether ${hybridBadge} [${uptime}s]`;
        } catch {
            this._item.text = '$(circle-slash) Aether offline';
        }
    }

    public dispose(): void {
        if (this._timer !== null) {
            clearInterval(this._timer);
        }
        this._item.dispose();
    }
}
