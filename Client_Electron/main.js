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

        // Spawn python
        const python = spawn('python', args); 

        let resultData = '';
        let errorData = '';
        
        python.stdout.on('data', (data) => {
            resultData += data.toString();
        });

        python.stderr.on('data', (data) => {
            errorData += data.toString();
        });

        python.on('close', async (code) => {
            // --- DEBUG LOGGING ---
            console.log(`[API] ${method} ${endpoint}`);
            console.log(`[RAW RESPONSE]:`, resultData); 
            if (errorData) console.error(`[PYTHON ERROR]:`, errorData);
            // ---------------------

            try {
                // Clean the output: remove any extra whitespace or newlines
                const cleanJson = resultData.trim();
                const result = JSON.parse(cleanJson);

                // QR Code Interception (Keep your existing logic here)
                if (endpoint === '/api/auth/register' && result.success && result.otpauth_url) {
                    const QRCode = require('qrcode');
                    try {
                        result.qrCode = await QRCode.toDataURL(result.otpauth_url);
                    } catch (err) { console.error("QR Error", err); }
                }

                resolve(result);
            } catch (e) {
                console.error("JSON Parse Error:", e);
                // Return a clear error so the UI knows what happened
                resolve({ 
                    success: false, 
                    error: "Client Parse Error. Check Terminal for details." 
                });
            }
        });
    });
});


app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});