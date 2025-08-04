document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const errorDiv = document.getElementById('error');
    const reportContent = document.getElementById('reportContent');
    const downloadBtn = document.getElementById('downloadBtn');

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const domain = document.getElementById('domain').value;
        const fullPortScan = document.getElementById('fullPortScan').checked;
        const wordlistFile = document.getElementById('wordlist').files[0];


        // show loading, hide results and error
        loadingDiv.classList.remove('d-none');
        resultsDiv.classList.add('d-none');
        errorDiv.classList.add('d-none');

        try {
            let customWordlist = null;

            if (wordlistFile) {
                customWordlist = wordlistFile.name;
            }

            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain,
                    fullPortScan,
                    customWordlist
                })
            });

            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            // displaying results
            reportContent.textContent = data.report;
            resultsDiv.classList.remove('d-none');

            // setting up download button
            downloadBtn.onclick = () => {
                const blob = new Blob([data.report], { type: 'type/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'recon_report_${domain}_${new Date().toISOString()}.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            };
        } catch (errr) {
            errorDiv.textContent = 'Error: ${err.message}';
        } finally {
            loadingDiv.classList.add('d-none');
        }
    });
});