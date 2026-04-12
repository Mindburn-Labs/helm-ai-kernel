import * as vscode from 'vscode';

/**
 * HELM Governance VS Code Extension
 *
 * Provides:
 * - CEL policy syntax highlighting
 * - ProofGraph DAG visualization
 * - Receipt inspection panel
 * - Real-time compliance score widget
 * - Policy evaluation commands
 */

let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
    console.log('HELM Governance extension activated');

    // Status bar: compliance score
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.command = 'helm.complianceScore';
    statusBarItem.text = '$(shield) HELM: Loading...';
    statusBarItem.tooltip = 'HELM Compliance Score';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('helm.verifyReceipt', verifyReceipt),
        vscode.commands.registerCommand('helm.complianceScore', showComplianceScore),
        vscode.commands.registerCommand('helm.proofgraphVisualize', visualizeProofGraph),
        vscode.commands.registerCommand('helm.evaluatePolicy', evaluatePolicy),
        vscode.commands.registerCommand('helm.inspectDecision', inspectDecision),
    );

    // Register tree data providers
    const complianceProvider = new ComplianceTreeProvider();
    const receiptsProvider = new ReceiptsTreeProvider();
    const agentsProvider = new AgentsTreeProvider();

    vscode.window.registerTreeDataProvider('helm.complianceView', complianceProvider);
    vscode.window.registerTreeDataProvider('helm.receiptsView', receiptsProvider);
    vscode.window.registerTreeDataProvider('helm.agentsView', agentsProvider);

    // Start polling compliance scores
    pollComplianceScore();
    const interval = setInterval(pollComplianceScore, 30000); // every 30s
    context.subscriptions.push({ dispose: () => clearInterval(interval) });
}

export function deactivate() {
    statusBarItem?.dispose();
}

// ── Commands ──────────────────────────────────────────────────

async function verifyReceipt() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }

    const content = editor.document.getText();
    try {
        const receipt = JSON.parse(content);
        const serverUrl = getServerUrl();

        const response = await fetch(`${serverUrl}/api/v1/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ receipt }),
        });

        if (response.ok) {
            const result = await response.json();
            vscode.window.showInformationMessage(
                `Receipt verified: ${result.valid ? 'VALID' : 'INVALID'} — ${result.reason || 'signature OK'}`
            );
        } else {
            vscode.window.showErrorMessage(`Verification failed: ${response.statusText}`);
        }
    } catch (err) {
        vscode.window.showErrorMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
}

async function showComplianceScore() {
    const serverUrl = getServerUrl();
    try {
        const response = await fetch(`${serverUrl}/api/v1/compliance/scores`);
        if (!response.ok) {
            vscode.window.showErrorMessage('Failed to fetch compliance scores');
            return;
        }

        const scores = await response.json() as Record<string, { score: number; framework: string }>;
        const items = Object.entries(scores).map(([framework, data]) => ({
            label: `${framework}: ${data.score}/100`,
            description: data.score >= 90 ? 'Compliant' : data.score >= 70 ? 'Warning' : 'Non-compliant',
            iconPath: data.score >= 90
                ? new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'))
                : data.score >= 70
                    ? new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconQueued'))
                    : new vscode.ThemeIcon('error', new vscode.ThemeColor('testing.iconFailed')),
        }));

        vscode.window.showQuickPick(items, {
            title: 'HELM Compliance Scores',
            placeHolder: 'Select a framework for details',
        });
    } catch {
        vscode.window.showWarningMessage('HELM server not reachable. Start with: helm server');
    }
}

async function visualizeProofGraph() {
    const panel = vscode.window.createWebviewPanel(
        'helmProofGraph',
        'HELM ProofGraph',
        vscode.ViewColumn.One,
        { enableScripts: true }
    );

    const serverUrl = getServerUrl();
    try {
        const response = await fetch(`${serverUrl}/api/v1/proofgraph/nodes?limit=100`);
        const nodes = response.ok ? await response.json() : [];

        panel.webview.html = getProofGraphHTML(nodes);
    } catch {
        panel.webview.html = getProofGraphHTML([]);
    }
}

async function evaluatePolicy() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const text = editor.document.getText();
    const serverUrl = getServerUrl();

    try {
        const response = await fetch(`${serverUrl}/api/v1/policy/evaluate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ expression: text }),
        });

        if (response.ok) {
            const result = await response.json();
            vscode.window.showInformationMessage(`Policy evaluation: ${JSON.stringify(result)}`);
        }
    } catch {
        vscode.window.showWarningMessage('HELM server not reachable');
    }
}

async function inspectDecision() {
    const input = await vscode.window.showInputBox({
        prompt: 'Enter Decision ID',
        placeHolder: 'dec-...',
    });
    if (!input) return;

    const serverUrl = getServerUrl();
    try {
        const response = await fetch(`${serverUrl}/api/v1/decisions/${input}`);
        if (response.ok) {
            const decision = await response.json();
            const doc = await vscode.workspace.openTextDocument({
                content: JSON.stringify(decision, null, 2),
                language: 'json',
            });
            vscode.window.showTextDocument(doc);
        }
    } catch {
        vscode.window.showWarningMessage('HELM server not reachable');
    }
}

// ── Status Bar ────────────────────────────────────────────────

async function pollComplianceScore() {
    const serverUrl = getServerUrl();
    try {
        const response = await fetch(`${serverUrl}/api/v1/compliance/scores`);
        if (response.ok) {
            const scores = await response.json() as Record<string, { score: number }>;
            const values = Object.values(scores).map((s) => s.score);
            const avg = values.length > 0
                ? Math.round(values.reduce((a, b) => a + b, 0) / values.length)
                : 0;

            const icon = avg >= 90 ? '$(pass)' : avg >= 70 ? '$(warning)' : '$(error)';
            statusBarItem.text = `${icon} HELM: ${avg}/100`;
            statusBarItem.color = avg >= 90 ? undefined : avg >= 70 ? '#ffa500' : '#ff0000';
        }
    } catch {
        statusBarItem.text = '$(shield) HELM: Offline';
        statusBarItem.color = '#888888';
    }
}

// ── Tree Data Providers ───────────────────────────────────────

class ComplianceTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    getTreeItem(element: vscode.TreeItem): vscode.TreeItem { return element; }
    async getChildren(): Promise<vscode.TreeItem[]> {
        const serverUrl = getServerUrl();
        try {
            const response = await fetch(`${serverUrl}/api/v1/compliance/scores`);
            if (!response.ok) return [new vscode.TreeItem('Server unavailable')];
            const scores = await response.json() as Record<string, { score: number; framework: string }>;
            return Object.entries(scores).map(([fw, data]) => {
                const item = new vscode.TreeItem(`${fw}: ${data.score}/100`);
                item.iconPath = data.score >= 90
                    ? new vscode.ThemeIcon('pass')
                    : new vscode.ThemeIcon('warning');
                return item;
            });
        } catch {
            return [new vscode.TreeItem('Start HELM server to view scores')];
        }
    }
}

class ReceiptsTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    getTreeItem(element: vscode.TreeItem): vscode.TreeItem { return element; }
    async getChildren(): Promise<vscode.TreeItem[]> {
        return [new vscode.TreeItem('Recent receipts will appear here')];
    }
}

class AgentsTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    getTreeItem(element: vscode.TreeItem): vscode.TreeItem { return element; }
    async getChildren(): Promise<vscode.TreeItem[]> {
        return [new vscode.TreeItem('Governed agents will appear here')];
    }
}

// ── ProofGraph Webview ────────────────────────────────────────

function getProofGraphHTML(nodes: any[]): string {
    const nodeData = JSON.stringify(nodes);
    return `<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: var(--vscode-font-family); background: var(--vscode-editor-background); color: var(--vscode-editor-foreground); padding: 20px; }
        .node { display: inline-block; margin: 8px; padding: 12px; border: 1px solid var(--vscode-panel-border); border-radius: 6px; }
        .node-INTENT { border-left: 4px solid #4caf50; }
        .node-ATTESTATION { border-left: 4px solid #2196f3; }
        .node-EFFECT { border-left: 4px solid #ff9800; }
        .node-TRUST_EVENT { border-left: 4px solid #9c27b0; }
        .node-TRUST_SCORE { border-left: 4px solid #e91e63; }
        .node-ZK_PROOF { border-left: 4px solid #00bcd4; }
        h1 { font-size: 1.4em; margin-bottom: 16px; }
        .meta { font-size: 0.85em; color: var(--vscode-descriptionForeground); }
        .empty { text-align: center; padding: 40px; }
    </style>
</head>
<body>
    <h1>HELM ProofGraph</h1>
    <div id="graph"></div>
    <script>
        const nodes = ${nodeData};
        const container = document.getElementById('graph');
        if (nodes.length === 0) {
            container.innerHTML = '<div class="empty">No ProofGraph nodes found. Start the HELM server and run some governed operations.</div>';
        } else {
            nodes.forEach(node => {
                const div = document.createElement('div');
                div.className = 'node node-' + (node.kind || 'UNKNOWN');
                div.innerHTML = '<strong>' + (node.kind || 'UNKNOWN') + '</strong>'
                    + '<div class="meta">Hash: ' + (node.node_hash || '').substring(0, 16) + '...</div>'
                    + '<div class="meta">Lamport: ' + (node.lamport || 0) + '</div>'
                    + '<div class="meta">Principal: ' + (node.principal || 'N/A') + '</div>';
                container.appendChild(div);
            });
        }
    </script>
</body>
</html>`;
}

// ── Helpers ───────────────────────────────────────────────────

function getServerUrl(): string {
    return vscode.workspace.getConfiguration('helm').get('serverUrl', 'http://localhost:8080');
}
