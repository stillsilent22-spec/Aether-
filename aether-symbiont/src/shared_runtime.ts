import * as fs from 'fs';
import * as path from 'path';

export interface HybridSymbiontSettings {
    enabled: boolean;
    pythonPath: string;
    serverPath: string;
    host: string;
    port: number;
}

export interface HybridRuntimeStatus {
    bridge_running: boolean;
    symbiont_running: boolean;
    bridge_pid: number;
    symbiont_pid: number;
    symbiont_host: string;
    symbiont_port: number;
    last_error: string;
    last_tick: string;
}

export interface VscodeRuntimeStatus {
    active: boolean;
    pythonPath: string;
    serverPath: string;
    reqMode: string;
    sharedSettings: boolean;
    lastError: string;
    updatedAt: string;
}

const DEFAULT_SETTINGS: HybridSymbiontSettings = {
    enabled: true,
    pythonPath: 'python',
    serverPath: 'aether-symbiont/server/symbiont_server.py',
    host: '127.0.0.1',
    port: 38571,
};

export function repoRootFromExtension(extensionPath: string): string {
    return path.resolve(extensionPath, '..');
}

export function readSharedSymbiontSettings(repoRoot: string): HybridSymbiontSettings {
    const settingsPath = path.join(repoRoot, 'data', 'settings.json');
    try {
        const raw = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
        const hybrid = raw?.hybrid;
        const symbiont = hybrid?.symbiont;
        return {
            enabled: Boolean(symbiont?.enabled ?? DEFAULT_SETTINGS.enabled),
            pythonPath: String(symbiont?.python_path ?? DEFAULT_SETTINGS.pythonPath),
            serverPath: String(symbiont?.server_path ?? DEFAULT_SETTINGS.serverPath),
            host: String(symbiont?.host ?? DEFAULT_SETTINGS.host),
            port: Number(symbiont?.port ?? DEFAULT_SETTINGS.port),
        };
    } catch {
        return { ...DEFAULT_SETTINGS };
    }
}

export function readHybridStatus(repoRoot: string): HybridRuntimeStatus | undefined {
    const statusPath = path.join(repoRoot, 'data', 'interbus', 'hybrid_status.json');
    try {
        return JSON.parse(fs.readFileSync(statusPath, 'utf-8')) as HybridRuntimeStatus;
    } catch {
        return undefined;
    }
}

export function writeVscodeRuntimeStatus(repoRoot: string, status: VscodeRuntimeStatus): void {
    const statusPath = path.join(repoRoot, 'data', 'interbus', 'vscode_symbiont_status.json');
    fs.mkdirSync(path.dirname(statusPath), { recursive: true });
    fs.writeFileSync(statusPath, JSON.stringify(status, null, 2), 'utf-8');
}
