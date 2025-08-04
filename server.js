const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 3000;

// middleware
app.use(express.json());
app.use(express.static('public'));

// API endpoint to run the recon tool
app.post('/api/scan', (req, res) =>  {
    const { domain, fullPortScan, customWordlist } = req.body;

    let command = 'python3 recon_tool.py "${domain}"';
    if (fullPortScan) command += ' --full-port-scan';
    if (customWordlist) command += ' --subdomain-wordlist "${customWordlist}"';

    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr });
        }

        // findin the latest report file
        const reportsDir = path.join(__dirname);
        const files = fs.readdirSync(reportsDir)
            .filter(file => file.startsWith('recon_report_${domain}_'))
            .sort()
            .reverse();

        if (files.length > 0) {
            const reportPath = path.json(reportsDir, files[0]);
            const reportContent = fs.readFileSync(reportPath, 'utf-8');
            res.json({ report: reportContent });
        }else {
            res.status(404).json({ error: 'Report not found' });
        }
    });
});

// serve the FE
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log('Server running on http://localhost:${PORT}');
});

