const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const https = require('https');
// 1. Re-import QRCode (it is in your node_modules)
const QRCode = require('qrcode');

let mainWindow;

// Server URL - UPDATE THIS to your remote server
const SERVER_URL = 'http://192.168.2.234:3000';

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

// --- HTTP API HANDLER ---
ipcMain.handle('api-request', async (event, { endpoint, method, body }) => {
    return new Promise((resolve) => {
        const url = new URL(endpoint, SERVER_URL);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname + url.search,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = httpModule.request(options, (res) => {
            let resultData = '';

            res.on('data', (chunk) => {
                resultData += chunk.toString();
            });

            res.on('end', async () => {
                console.log(`[API] ${method} ${endpoint}`);
                console.log(`[RAW RESPONSE]:`, resultData);

                try {
                    const cleanJson = resultData.trim();
                    const result = JSON.parse(cleanJson);

                    // QR Code Interception
                    if (endpoint === '/api/auth/register' && result.success && result.otpauth_url) {
                        try {
                            result.qrCode = await QRCode.toDataURL(result.otpauth_url);
                        } catch (err) { console.error("QR Error", err); }
                    }

                    resolve(result);
                } catch (e) {
                    console.error("JSON Parse Error:", e);
                    resolve({
                        success: false,
                        error: "Client Parse Error. Check Terminal for details."
                    });
                }
            });
        });

        req.on('error', (e) => {
            console.error("Request Error:", e);
            resolve({
                success: false,
                error: `Connection Error: ${e.message}`
            });
        });

        if (body && method !== 'GET') {
            req.write(JSON.stringify(body));
        }

        req.end();
    });
});


app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});