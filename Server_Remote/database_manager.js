const fs = require('fs').promises;
const path = require('path');
const { Mutex } = require('async-mutex');

const DATA_DIR = path.join(__dirname, 'data');
const locks = {
    users: new Mutex(),
    emails: new Mutex(),
    reputation: new Mutex()
};

async function init() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
        const files = ['users.json', 'emails.json', 'reputation.json'];
        for (const f of files) {
            try {
                await fs.access(path.join(DATA_DIR, f));
            } catch {
                await fs.writeFile(path.join(DATA_DIR, f), '[]');
            }
        }
    } catch(e) { console.error("DB Init Error", e); }
}

async function read(file) {
    const release = await locks[file].acquire();
    try {
        const raw = await fs.readFile(path.join(DATA_DIR, `${file}.json`), 'utf8');
        return JSON.parse(raw);
    } catch { return []; } 
    finally { release(); }
}

async function write(file, data) {
    const release = await locks[file].acquire();
    try {
        await fs.writeFile(path.join(DATA_DIR, `${file}.json`), JSON.stringify(data, null, 2));
    } finally { release(); }
}

module.exports = { init, read, write };