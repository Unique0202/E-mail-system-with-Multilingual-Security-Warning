const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

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

        // Spawn python process
        const python = spawn('python', args); // Or 'python3' on Mac/Linux

        let result = '';
        
        python.stdout.on('data', (data) => {
            result += data.toString();
        });

        python.stderr.on('data', (data) => {
            console.error(`Python Error: ${data}`);
        });

        python.on('close', (code) => {
            try {
                resolve(JSON.parse(result));
            } catch (e) {
                resolve({ success: false, error: "Failed to parse Python response: " + result });
            }
        });
    });
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});