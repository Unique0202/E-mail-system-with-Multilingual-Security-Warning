const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
// 1. Re-import QRCode (it is in your node_modules)
const QRCode = require('qrcode'); 

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });

    mainWindow.loadFile('html/login.html');
}

// --- PYTHON CONNECTOR HANDLER ---
ipcMain.handle('api-request', async (event, { endpoint, method, body }) => {
    return new Promise((resolve) => {
        const scriptPath = path.join(__dirname, 'python', 'client_connector.py');
        const args = [scriptPath, method, endpoint];
        
        if (body) {
            args.push(JSON.stringify(body));
        }

        const python = spawn('python', args);

        let resultData = '';
        
        python.stdout.on('data', (data) => {
            resultData += data.toString();
        });

        python.stderr.on('data', (data) => {
            console.error(`Python Error: ${data}`);
        });

        python.on('close', async (code) => {
            try {
                // 2. Parse the JSON from Python
                const result = JSON.parse(resultData);

                // 3. INTERCEPT REGISTRATION: Generate QR Code here
                if (endpoint === '/api/auth/register' && result.success && result.otpauth_url) {
                    try {
                        // Convert text URL to Image Data URI
                        result.qrCode = await QRCode.toDataURL(result.otpauth_url);
                    } catch (qrErr) {
                        console.error("QR Generation failed:", qrErr);
                    }
                }

                resolve(result);
            } catch (e) {
                resolve({ success: false, error: "Failed to parse Python response: " + resultData });
            }
        });
    });
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});