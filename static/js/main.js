// ReconMaster - Advanced Reconnaissance Tool JS

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const apiStatuses = {
        shodan: document.getElementById('shodan-status'),
        hunter: document.getElementById('hunter-status'),
        gemini: document.getElementById('gemini-status')
    };
    
    const scanForm = document.getElementById('scan-form');
    const toggleAllBtn = document.getElementById('toggle-all');
    const resultsSection = document.getElementById('results-section');
    const targetDisplay = document.getElementById('target-display');
    const scanStatus = document.getElementById('scan-status');
    const progressBar = document.getElementById('scan-progress-bar').querySelector('.progress-fill');
    const progressText = document.querySelector('.progress-text');
    const toolList = document.getElementById('tool-list');
    const toolOutput = document.getElementById('tool-output');
    const downloadReportBtn = document.getElementById('download-report');
    const cancelScanBtn = document.getElementById('cancel-scan');
    const reportsTable = document.getElementById('reports-table').querySelector('tbody');
    const noReportsMsg = document.getElementById('no-reports');
    
    // Modal Elements
    const analysisModal = document.getElementById('analysis-modal');
    const closeModalBtn = document.querySelector('.close-modal');
    const closeAnalysisBtn = document.getElementById('close-analysis');
    const aiAnalysisContent = document.getElementById('ai-analysis-content');
    
    // Global variables
    let currentTarget = '';
    let isScanning = false;
    let toolsCompleted = 0;
    let totalTools = 0;
    let currentReport = '';
    let statusCheckInterval = null;
    let allTools = [];
    
    // Check API Status
    function checkApiStatus() {
        fetch('/api/check')
            .then(response => response.json())
            .then(data => {
                updateApiStatus('shodan', data.shodan);
                updateApiStatus('hunter', data.hunter);
                updateApiStatus('gemini', data.gemini);
            })
            .catch(error => {
                console.error('Error checking API status:', error);
                Object.keys(apiStatuses).forEach(api => updateApiStatus(api, false));
            });
    }
    
    function updateApiStatus(api, isActive) {
        const element = apiStatuses[api];
        if (element) {
            element.classList.remove('active', 'inactive');
            element.classList.add(isActive ? 'active' : 'inactive');
            element.title = `${api.charAt(0).toUpperCase() + api.slice(1)} API: ${isActive ? 'Connected' : 'Not Connected'}`;
        }
    }
    
    // Toggle all scan options
    toggleAllBtn.addEventListener('click', () => {
        const options = document.querySelectorAll('input[type="checkbox"]');
        const allChecked = Array.from(options).every(opt => opt.checked);
        
        options.forEach(option => {
            option.checked = !allChecked;
        });
    });
    
    // Start scan
    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const target = document.getElementById('target').value.trim();
        if (!target) return;
        
        // Gather all options
        const options = {};
        document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
            options[checkbox.id] = checkbox.checked;
        });
        
        // Reset UI
        resetScanUI();
        showResults();
        
        // Set current target and status
        currentTarget = target;
        isScanning = true;
        targetDisplay.textContent = `Target: ${target}`;
        
        // Make API request to start scan
        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target,
                options
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                startStatusChecking();
            } else {
                showError('Failed to start scan: ' + data.error);
            }
        })
        .catch(error => {
            showError('Network error: ' + error.message);
        });
    });
    
    // Cancel scan
    cancelScanBtn.addEventListener('click', () => {
        if (confirm('Are you sure you want to cancel the scan?')) {
            stopStatusChecking();
            scanStatus.innerHTML = '<i class="fas fa-times-circle"></i> Cancelled';
            scanStatus.className = 'status error';
            isScanning = false;
            
            // In a real implementation, you'd make an API call to cancel the scan
            // For this demo, we'll just update the UI
        }
    });
    
    // Download report
    downloadReportBtn.addEventListener('click', () => {
        if (currentReport) {
            window.location.href = `/api/reports/${currentReport}`;
        }
    });
    
    // Close modal handlers
    closeModalBtn.addEventListener('click', () => {
        analysisModal.style.display = 'none';
    });
    
    closeAnalysisBtn.addEventListener('click', () => {
        analysisModal.style.display = 'none';
    });
    
    window.addEventListener('click', (e) => {
        if (e.target === analysisModal) {
            analysisModal.style.display = 'none';
        }
    });
    
    // Show AI analysis
    function showAIAnalysis(analysis) {
        aiAnalysisContent.innerHTML = marked.parse(analysis);
        analysisModal.style.display = 'block';
    }
    
    // Check status periodically
    function startStatusChecking() {
        statusCheckInterval = setInterval(checkScanStatus, 2000);
    }
    
    function stopStatusChecking() {
        if (statusCheckInterval) {
            clearInterval(statusCheckInterval);
            statusCheckInterval = null;
        }
    }
    
    function checkScanStatus() {
        fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                if (data.results && data.results.length > 0) {
                    processResults(data.results);
                }
                
                if (data.status === 'idle' && isScanning) {
                    // Scan might be complete
                    loadReports();
                    setTimeout(() => {
                        if (toolsCompleted === totalTools && totalTools > 0) {
                            completeScanning();
                        }
                    }, 2000);
                }
            })
            .catch(error => {
                console.error('Error checking scan status:', error);
            });
    }
    
    function processResults(results) {
        results.forEach(result => {
            // Add tool to the list if not already added
            const existingTool = allTools.find(t => t.tool === result.tool && t.description === result.description);
            
            if (!existingTool) {
                allTools.push(result);
                totalTools++;
                
                // Add to UI
                addToolToUI(result);
            } else {
                // Update existing tool
                if (!existingTool.completed && (!result.error || Object.keys(result.output || {}).length > 0)) {
                    existingTool.completed = true;
                    existingTool.output = result.output || existingTool.output;
                    existingTool.error = result.error || existingTool.error;
                    
                    // Update UI for this tool
                    updateToolInUI(existingTool);
                    
                    // Count completed tools
                    toolsCompleted++;
                    updateProgress();
                }
            }
        });
    }
    
    function addToolToUI(tool) {
        // Add to tool list
        const li = document.createElement('li');
        li.setAttribute('data-tool', `${tool.tool}-${tool.description}`);
        li.innerHTML = `
            <span>${tool.tool}</span>
            <span class="tool-status pending"></span>
        `;
        li.addEventListener('click', () => {
            selectTool(tool);
        });
        toolList.appendChild(li);
    }
    
    function updateToolInUI(tool) {
        const li = document.querySelector(`[data-tool="${tool.tool}-${tool.description}"]`);
        if (li) {
            const statusDot = li.querySelector('.tool-status');
            statusDot.classList.remove('pending', 'running', 'completed', 'error');
            statusDot.classList.add(tool.error ? 'error' : 'completed');
        }
    }
    
    function selectTool(tool) {
        // Highlight the selected tool
        const allTools = document.querySelectorAll('#tool-list li');
        allTools.forEach(t => t.classList.remove('active'));
        
        const selectedTool = document.querySelector(`[data-tool="${tool.tool}-${tool.description}"]`);
        if (selectedTool) {
            selectedTool.classList.add('active');
        }
        
        // Display tool output
        if (tool.output) {
            let outputContent = '';
            
            if (typeof tool.output === 'string') {
                outputContent = tool.output;
            } else if (Array.isArray(tool.output)) {
                outputContent = tool.output.join('\n');
            } else if (typeof tool.output === 'object') {
                outputContent = JSON.stringify(tool.output, null, 2);
            }
            
            toolOutput.innerHTML = `<pre>${escapeHtml(outputContent)}</pre>`;
        } else if (tool.error) {
            toolOutput.innerHTML = `<div class="error-message">Error: ${escapeHtml(tool.error)}</div>`;
        } else {
            toolOutput.innerHTML = `<div class="placeholder-message">
                <i class="fas fa-spinner fa-spin fa-2x"></i>
                <p>Running ${tool.tool}...</p>
            </div>`;
        }
    }
    
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    function updateProgress() {
        const progress = (toolsCompleted / totalTools) * 100;
        progressBar.style.width = `${progress}%`;
        progressText.textContent = `${Math.round(progress)}%`;
    }
    
    function completeScanning() {
        stopStatusChecking();
        isScanning = false;
        
        // Update UI
        scanStatus.innerHTML = '<i class="fas fa-check-circle"></i> Completed';
        scanStatus.className = 'status completed';
        progressBar.style.width = '100%';
        progressText.textContent = '100%';
        
        // Enable download button
        downloadReportBtn.disabled = false;
        
        // If Gemini analysis was done, offer to show it
        const geminiTool = allTools.find(t => t.tool === 'Gemini AI');
        if (geminiTool && geminiTool.output && geminiTool.output.analysis) {
            setTimeout(() => {
                if (confirm('Gemini AI analysis is complete. Would you like to see the results?')) {
                    showAIAnalysis(geminiTool.output.analysis);
                }
            }, 1000);
        }
    }
    
    function showError(message) {
        scanStatus.innerHTML = '<i class="fas fa-times-circle"></i> Error';
        scanStatus.className = 'status error';
        toolOutput.innerHTML = `<div class="error-message">${message}</div>`;
        stopStatusChecking();
        isScanning = false;
    }
    
    function resetScanUI() {
        // Clear tool list and output
        toolList.innerHTML = '';
        toolOutput.innerHTML = `<div class="placeholder-message">
            <i class="fas fa-terminal fa-3x"></i>
            <p>Tool output will appear here</p>
        </div>`;
        
        // Reset progress
        progressBar.style.width = '0%';
        progressText.textContent = '0%';
        
        // Reset status
        scanStatus.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running';
        scanStatus.className = 'status running';
        
        // Reset variables
        allTools = [];
        toolsCompleted = 0;
        totalTools = 0;
        currentReport = '';
        
        // Disable download button
        downloadReportBtn.disabled = true;
    }
    
    function showResults() {
        resultsSection.classList.remove('hidden');
    }
    
    // Load saved reports
    function loadReports() {
        fetch('/api/reports')
            .then(response => response.json())
            .then(data => {
                if (data.reports && data.reports.length > 0) {
                    displayReports(data.reports);
                    noReportsMsg.style.display = 'none';
                } else {
                    reportsTable.innerHTML = '';
                    noReportsMsg.style.display = 'block';
                }
            })
            .catch(error => {
                console.error('Error loading reports:', error);
            });
    }
    
    function displayReports(reports) {
        reportsTable.innerHTML = '';
        
        reports.forEach(report => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${report.target}</td>
                <td>${report.timestamp}</td>
                <td>${formatFileSize(report.size)}</td>
                <td class="report-actions">
                    <button class="btn primary-btn" onclick="downloadReport('${report.filename}')">
                        <i class="fas fa-download"></i> Download
                    </button>
                    <button class="btn secondary-btn" onclick="viewReport('${report.filename}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                </td>
            `;
            reportsTable.appendChild(row);
        });
        
        // Update current report if scanning just completed
        if (isScanning && reports.length > 0) {
            currentReport = reports[0].filename;
        }
    }
    
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Global functions for report actions
    window.downloadReport = function(filename) {
        window.location.href = `/api/reports/${filename}`;
    };
    
    window.viewReport = function(filename) {
        // Open report in new tab (simplified view)
        window.open(`/api/reports/${filename}`, '_blank');
    };
    
    // Auto-refresh reports every 30 seconds
    setInterval(loadReports, 30000);
    
    // Initialize the application
    function init() {
        checkApiStatus();
        loadReports();
        
        // Set up form validation
        const targetInput = document.getElementById('target');
        targetInput.addEventListener('input', (e) => {
            const value = e.target.value.trim();
            const isValid = value && (isValidDomain(value) || isValidIP(value));
            
            if (value && !isValid) {
                e.target.setCustomValidity('Please enter a valid domain or IP address');
            } else {
                e.target.setCustomValidity('');
            }
        });
    }
    
    // Validation functions
    function isValidDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        return domainRegex.test(domain);
    }
    
    function isValidIP(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }
    
    // Notification system
    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'times-circle' : 'info-circle'}"></i>
            <span>${message}</span>
            <button class="close-notification" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add to body
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl+Enter to start scan
        if (e.ctrlKey && e.key === 'Enter') {
            const targetInput = document.getElementById('target');
            if (targetInput.value.trim() && !isScanning) {
                scanForm.dispatchEvent(new Event('submit'));
            }
        }
        
        // Escape to close modal
        if (e.key === 'Escape') {
            if (analysisModal.style.display === 'block') {
                analysisModal.style.display = 'none';
            }
        }
    });
    
    // Initialize the application
    init();
});

// Service Worker for offline functionality (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/js/sw.js')
            .then(registration => {
                console.log('SW registered: ', registration);
            })
            .catch(registrationError => {
                console.log('SW registration failed: ', registrationError);
            });
    });
}