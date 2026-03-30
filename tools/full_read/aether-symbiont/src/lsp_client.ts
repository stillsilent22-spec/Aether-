import * as cp from 'child_process';
import * as net from 'net';

/**
 * Minimal JSON-RPC 2.0 client that communicates with symbiont_server.py.
 * It can either spawn a local stdio server or attach to the shared hybrid TCP socket.
 */
export class SymbiontLanguageClient {
    private _process: cp.ChildProcess | null = null;
    private _socket: net.Socket | null = null;
    private _nextId = 1;
    private _pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
    private _buffer = '';
        private _auditLog: Array<{
            timestamp: string;
            method: string;
            params: object;
            result?: unknown;
            error?: string;
            direction: 'request' | 'response';
        }> = [];

    constructor(
        private readonly serverPath: string,
        private readonly pythonPath: string,
        private readonly sharedHost?: string,
        private readonly sharedPort?: number,
    ) {}

    async start(): Promise<void> {
        if (this.sharedHost && this.sharedPort) {
            const host = this.sharedHost;
            const port = this.sharedPort;
            await new Promise<void>((resolve, reject) => {
                const socket = net.createConnection(
                    { host, port },
                    () => resolve(),
                );
                socket.on('data', (chunk: Buffer) => {
                    this._buffer += chunk.toString('utf-8');
                    this._processBuffer();
                });
                socket.on('error', reject);
                socket.on('close', () => {
                    for (const { reject } of this._pending.values()) {
                        reject(new Error('Shared Symbiont socket closed'));
                    }
                    this._pending.clear();
                });
                this._socket = socket;
            });
            return;
        }

        this._process = cp.spawn(this.pythonPath, [this.serverPath], {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: process.env,
        });

        this._process.stderr?.on('data', (_data: Buffer) => {
            // Server logs go to stderr — forwarded silently for now.
        });

        this._process.stdout?.on('data', (chunk: Buffer) => {
            this._buffer += chunk.toString('utf-8');
            this._processBuffer();
        });

        this._process.on('exit', (code) => {
            for (const { reject } of this._pending.values()) {
                reject(new Error(`Server exited with code ${code}`));
            }
            this._pending.clear();
        });
    }

    async stop(): Promise<void> {
        this._socket?.end();
        this._socket?.destroy();
        this._socket = null;
        this._process?.kill();
        this._process = null;
    }

    async sendRequest(method: string, params: object): Promise<unknown> {
        return new Promise((resolve, reject) => {
            const id = this._nextId++;
            this._pending.set(id, { resolve, reject });
            const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params });
            const header = `Content-Length: ${Buffer.byteLength(msg, 'utf-8')}\r\n\r\n`;
            // Audit: Logge Request
            this._auditLog.push({
                timestamp: new Date().toISOString(),
                method,
                params,
                direction: 'request',
            });
            if (this._socket !== null) {
                this._socket.write(header + msg, 'utf-8');
            } else {
                this._process?.stdin?.write(header + msg, 'utf-8');
            }

            setTimeout(() => {
                if (this._pending.has(id)) {
                    this._pending.delete(id);
                    reject(new Error(`Request ${method} timed out`));
                }
            }, 15_000);
        });
    }

    private _processBuffer(): void {
        while (true) {
            const headerEnd = this._buffer.indexOf('\r\n\r\n');
            if (headerEnd === -1) break;
            const headerPart = this._buffer.slice(0, headerEnd);
            const match = /Content-Length:\s*(\d+)/i.exec(headerPart);
            if (!match) {
                this._buffer = this._buffer.slice(headerEnd + 4);
                continue;
            }
            const length = parseInt(match[1], 10);
            const bodyStart = headerEnd + 4;
            if (this._buffer.length < bodyStart + length) break;
            const body = this._buffer.slice(bodyStart, bodyStart + length);
            this._buffer = this._buffer.slice(bodyStart + length);
            try {
                const msg = JSON.parse(body);
                if (msg.id !== undefined && this._pending.has(msg.id)) {
                    const { resolve, reject } = this._pending.get(msg.id)!;
                    this._pending.delete(msg.id);
                    // Audit: Logge Response
                    const lastRequest = this._auditLog.slice().reverse().find(e => e.method === msg.method && e.direction === 'request');
                    this._auditLog.push({
                        timestamp: new Date().toISOString(),
                        method: msg.method || (lastRequest ? lastRequest.method : 'unknown'),
                        params: lastRequest ? lastRequest.params : {},
                        result: msg.result,
                        error: msg.error?.message,
                        direction: 'response',
                    });
                    if (msg.error) {
                        reject(new Error(msg.error.message ?? 'Unknown error'));
                    } else {
                        resolve(msg.result);
                    }
                }
            } catch {
                // Ignore malformed JSON frames.
            }
        }
    }
    // Exportiert das Audit-Log als JSON-String
    public exportAuditLog(): string {
        return JSON.stringify(this._auditLog, null, 2);
    }
}
