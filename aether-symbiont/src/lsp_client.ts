import * as cp from 'child_process';
import * as readline from 'readline';

/**
 * Minimal JSON-RPC 2.0 client that communicates with symbiont_server.py
 * via stdin/stdout (Content-Length framing — same as LSP).
 */
export class SymbiontLanguageClient {
    private _process: cp.ChildProcess | null = null;
    private _nextId = 1;
    private _pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
    private _buffer = '';

    constructor(
        private readonly serverPath: string,
        private readonly pythonPath: string,
    ) {}

    async start(): Promise<void> {
        this._process = cp.spawn(this.pythonPath, [this.serverPath], {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: process.env,
        });

        this._process.stderr?.on('data', (data: Buffer) => {
            // Server logs go to stderr — forward to VS Code output channel (silent)
        });

        this._process.stdout?.on('data', (chunk: Buffer) => {
            this._buffer += chunk.toString('utf-8');
            this._processBuffer();
        });

        this._process.on('exit', (code) => {
            // Reject all pending requests on exit
            for (const { reject } of this._pending.values()) {
                reject(new Error(`Server exited with code ${code}`));
            }
            this._pending.clear();
        });
    }

    async stop(): Promise<void> {
        this._process?.kill();
        this._process = null;
    }

    async sendRequest(method: string, params: object): Promise<unknown> {
        return new Promise((resolve, reject) => {
            const id = this._nextId++;
            this._pending.set(id, { resolve, reject });
            const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params });
            const header = `Content-Length: ${Buffer.byteLength(msg, 'utf-8')}\r\n\r\n`;
            this._process?.stdin?.write(header + msg, 'utf-8');

            // Timeout after 15s
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
            if (!match) { this._buffer = this._buffer.slice(headerEnd + 4); continue; }
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
                    if (msg.error) {
                        reject(new Error(msg.error.message ?? 'Unknown error'));
                    } else {
                        resolve(msg.result);
                    }
                }
            } catch {
                // Malformed JSON — ignore
            }
        }
    }
}
