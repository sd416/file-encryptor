// File Encryptor Web Application
class FileEncryptorApp {
    constructor() {
        this.selectedFiles = [];
        this.currentOperation = null;
        this.ws = null;
        this.theme = localStorage.getItem('theme') || 'light';
        
        this.init();
    }

    init() {
        this.setupTheme();
        this.setupEventListeners();
        this.setupDragDrop();
        this.setupWebSocket();
        this.loadServerStatus();
    }

    // Theme management
    setupTheme() {
        document.documentElement.setAttribute('data-theme', this.theme);
        const themeIcon = document.querySelector('.theme-icon');
        if (themeIcon) {
            themeIcon.textContent = this.theme === 'dark' ? '☀️' : '🌙';
        }
    }

    toggleTheme() {
        this.theme = this.theme === 'light' ? 'dark' : 'light';
        localStorage.setItem('theme', this.theme);
        this.setupTheme();
        this.showToast('Theme changed', `Switched to ${this.theme} mode`, 'success');
    }

    // Event listeners
    setupEventListeners() {
        // Theme toggle
        document.getElementById('theme-toggle').addEventListener('click', () => {
            this.toggleTheme();
        });

        // File selection
        document.getElementById('selectFilesBtn').addEventListener('click', () => {
            document.getElementById('fileInput').click();
        });

        document.getElementById('fileInput').addEventListener('change', (e) => {
            this.handleFiles(Array.from(e.target.files));
        });

        // Clear files
        document.getElementById('clearFilesBtn').addEventListener('click', () => {
            this.clearFiles();
        });

        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Method selection
        document.getElementById('encrypt-method').addEventListener('change', (e) => {
            this.toggleAuthMethod('encrypt', e.target.value);
        });

        document.getElementById('decrypt-method').addEventListener('change', (e) => {
            this.toggleAuthMethod('decrypt', e.target.value);
        });

        // Password visibility toggle
        document.getElementById('toggle-encrypt-password').addEventListener('click', () => {
            this.togglePasswordVisibility('encrypt-password');
        });

        document.getElementById('toggle-decrypt-password').addEventListener('click', () => {
            this.togglePasswordVisibility('decrypt-password');
        });

        // Operation buttons
        document.getElementById('startEncryptBtn').addEventListener('click', () => {
            this.startEncryption();
        });

        document.getElementById('startDecryptBtn').addEventListener('click', () => {
            this.startDecryption();
        });

        document.getElementById('generateKeysBtn').addEventListener('click', () => {
            this.generateKeys();
        });

        // Progress and results
        document.getElementById('cancelOperationBtn').addEventListener('click', () => {
            this.cancelOperation();
        });

        document.getElementById('newOperationBtn').addEventListener('click', () => {
            this.resetToStart();
        });

        // Modals
        document.getElementById('config-btn').addEventListener('click', () => {
            this.showConfigModal();
        });

        document.getElementById('status-btn').addEventListener('click', () => {
            this.showStatusModal();
        });

        document.getElementById('closeConfigModal').addEventListener('click', () => {
            this.hideModal();
        });

        document.getElementById('closeStatusModal').addEventListener('click', () => {
            this.hideModal();
        });

        document.getElementById('modalOverlay').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) {
                this.hideModal();
            }
        });
    }

    // Drag and drop
    setupDragDrop() {
        const dropZone = document.getElementById('dropZone');

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            if (!dropZone.contains(e.relatedTarget)) {
                dropZone.classList.remove('drag-over');
            }
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            
            const files = Array.from(e.dataTransfer.files);
            this.handleFiles(files);
        });
    }

    // WebSocket connection
    setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/progress`;

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.updateConnectionStatus('Connected');
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleProgressUpdate(data);
            };

            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus('Disconnected');
                
                // Attempt to reconnect after 3 seconds
                setTimeout(() => {
                    this.setupWebSocket();
                }, 3000);
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('Error');
            };
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            this.updateConnectionStatus('Error');
        }
    }

    // File handling
    handleFiles(files) {
        if (files.length === 0) return;

        this.selectedFiles = files;
        this.displaySelectedFiles();
        this.showOperationPanel();
        
        // Auto-detect operation based on file extensions
        const hasEncryptedFiles = files.some(file => file.name.endsWith('.enc'));
        if (hasEncryptedFiles) {
            this.switchTab('decrypt');
        } else {
            this.switchTab('encrypt');
        }

        this.showToast('Files selected', `${files.length} file(s) ready for processing`, 'success');
    }

    displaySelectedFiles() {
        const fileList = document.getElementById('fileList');
        const filesSection = document.getElementById('filesSection');

        fileList.innerHTML = '';

        this.selectedFiles.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <div class="file-icon">${this.getFileIcon(file.name)}</div>
                    <div class="file-details">
                        <h4>${file.name}</h4>
                        <p>${this.formatFileSize(file.size)}</p>
                    </div>
                </div>
                <button class="btn-icon" onclick="app.removeFile(${index})" title="Remove file">
                    ❌
                </button>
            `;
            fileList.appendChild(fileItem);
        });

        filesSection.style.display = 'block';
    }

    removeFile(index) {
        this.selectedFiles.splice(index, 1);
        
        if (this.selectedFiles.length === 0) {
            this.clearFiles();
        } else {
            this.displaySelectedFiles();
        }
    }

    clearFiles() {
        this.selectedFiles = [];
        document.getElementById('filesSection').style.display = 'none';
        document.getElementById('operationPanel').style.display = 'none';
        document.getElementById('fileInput').value = '';
        this.showToast('Files cleared', 'All selected files have been removed', 'success');
    }

    // UI state management
    showOperationPanel() {
        document.getElementById('operationPanel').style.display = 'block';
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}-content`).classList.add('active');
    }

    toggleAuthMethod(operation, method) {
        const passwordGroup = document.getElementById(`${operation}-password-group`);
        const keyGroup = document.getElementById(`${operation}-key-group`);

        if (method === 'password') {
            passwordGroup.classList.remove('hidden');
            keyGroup.classList.add('hidden');
        } else {
            passwordGroup.classList.add('hidden');
            keyGroup.classList.remove('hidden');
        }
    }

    togglePasswordVisibility(inputId) {
        const input = document.getElementById(inputId);
        const button = document.getElementById(`toggle-${inputId}`);
        
        if (input.type === 'password') {
            input.type = 'text';
            button.textContent = '🙈';
        } else {
            input.type = 'password';
            button.textContent = '👁️';
        }
    }

    // Operations
    async startEncryption() {
        if (this.selectedFiles.length === 0) {
            this.showToast('No files', 'Please select files to encrypt', 'error');
            return;
        }

        const method = document.getElementById('encrypt-method').value;
        const password = document.getElementById('encrypt-password').value;
        const keyFile = document.getElementById('encrypt-key-file').files[0];

        if (method === 'password' && !password) {
            this.showToast('Missing password', 'Please enter a password', 'error');
            return;
        }

        if (method === 'key' && !keyFile) {
            this.showToast('Missing key file', 'Please select a public key file', 'error');
            return;
        }

        this.showProgressSection('Encrypting Files...');

        try {
            const formData = new FormData();
            
            this.selectedFiles.forEach(file => {
                formData.append('files', file);
            });
            
            formData.append('method', method);
            if (method === 'password') {
                formData.append('password', password);
            } else {
                formData.append('keyFile', keyFile);
            }

            const response = await fetch('/api/v1/encrypt', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok) {
                this.currentOperation = result.id;
                this.showToast('Encryption started', 'Your files are being encrypted', 'success');
            } else {
                throw new Error(result.message || 'Encryption failed');
            }
        } catch (error) {
            this.showToast('Encryption failed', error.message, 'error');
            this.hideProgressSection();
        }
    }

    async startDecryption() {
        if (this.selectedFiles.length === 0) {
            this.showToast('No files', 'Please select files to decrypt', 'error');
            return;
        }

        const method = document.getElementById('decrypt-method').value;
        const password = document.getElementById('decrypt-password').value;
        const keyFile = document.getElementById('decrypt-key-file').files[0];

        if (method === 'password' && !password) {
            this.showToast('Missing password', 'Please enter a password', 'error');
            return;
        }

        if (method === 'key' && !keyFile) {
            this.showToast('Missing key file', 'Please select a private key file', 'error');
            return;
        }

        this.showProgressSection('Decrypting Files...');

        try {
            const formData = new FormData();
            
            this.selectedFiles.forEach(file => {
                formData.append('files', file);
            });
            
            formData.append('method', method);
            if (method === 'password') {
                formData.append('password', password);
            } else {
                formData.append('keyFile', keyFile);
            }

            const response = await fetch('/api/v1/decrypt', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok) {
                this.currentOperation = result.id;
                this.showToast('Decryption started', 'Your files are being decrypted', 'success');
            } else {
                throw new Error(result.message || 'Decryption failed');
            }
        } catch (error) {
            this.showToast('Decryption failed', error.message, 'error');
            this.hideProgressSection();
        }
    }

    async generateKeys() {
        const keyName = document.getElementById('key-name').value || 'key';
        const keySize = parseInt(document.getElementById('key-size').value);

        try {
            const response = await fetch('/api/v1/generate-keys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    keyName: keyName,
                    keySize: keySize
                })
            });

            const result = await response.json();

            if (response.ok) {
                this.showToast('Keys generated', 'RSA key pair generated successfully', 'success');
                this.downloadKeys(result);
            } else {
                throw new Error(result.message || 'Key generation failed');
            }
        } catch (error) {
            this.showToast('Key generation failed', error.message, 'error');
        }
    }

    downloadKeys(keyData) {
        // Download private key
        this.downloadFile(keyData.privateKey, keyData.privateFile, 'application/x-pem-file');
        
        // Download public key
        setTimeout(() => {
            this.downloadFile(keyData.publicKey, keyData.publicFile, 'application/x-pem-file');
        }, 100);
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Progress handling
    showProgressSection(title) {
        document.getElementById('operationTitle').textContent = title;
        document.getElementById('progressPercent').textContent = '0%';
        document.getElementById('progressFiles').textContent = '0/0 files';
        document.getElementById('progressFill').style.width = '0%';
        document.getElementById('currentFile').textContent = '';
        
        document.getElementById('operationPanel').style.display = 'none';
        document.getElementById('progressSection').classList.remove('hidden');
    }

    hideProgressSection() {
        document.getElementById('progressSection').classList.add('hidden');
        document.getElementById('operationPanel').style.display = 'block';
    }

    handleProgressUpdate(data) {
        if (data.operationId !== this.currentOperation) return;

        const progressPercent = Math.round(data.progress * 100);
        document.getElementById('progressPercent').textContent = `${progressPercent}%`;
        document.getElementById('progressFiles').textContent = `${data.filesComplete}/${data.totalFiles} files`;
        document.getElementById('progressFill').style.width = `${progressPercent}%`;
        
        if (data.currentFile) {
            document.getElementById('currentFile').textContent = `Processing: ${data.currentFile}`;
        }

        if (data.status === 'completed') {
            this.handleOperationComplete();
        } else if (data.status === 'error') {
            this.showToast('Operation failed', data.message || 'An error occurred', 'error');
            this.hideProgressSection();
        }
    }

    async handleOperationComplete() {
        try {
            const response = await fetch(`/api/v1/operations/${this.currentOperation}`);
            const result = await response.json();

            if (response.ok) {
                this.showResults(result);
            } else {
                throw new Error('Failed to get operation results');
            }
        } catch (error) {
            this.showToast('Error', 'Failed to retrieve operation results', 'error');
            this.hideProgressSection();
        }
    }

    showResults(operationData) {
        document.getElementById('progressSection').classList.add('hidden');
        
        const resultsSection = document.getElementById('resultsSection');
        const resultsTitle = document.getElementById('resultsTitle');
        const resultsSummary = document.getElementById('resultsSummary');
        const fileResults = document.getElementById('fileResults');

        resultsTitle.textContent = 'Operation Complete';
        
        const successCount = operationData.files.filter(f => f.status === 'success').length;
        const errorCount = operationData.files.filter(f => f.status === 'error').length;
        
        resultsSummary.innerHTML = `
            <span class="text-success">${successCount} successful</span>
            ${errorCount > 0 ? `<span class="text-error">${errorCount} failed</span>` : ''}
        `;

        fileResults.innerHTML = '';
        operationData.files.forEach(file => {
            const resultItem = document.createElement('div');
            resultItem.className = `result-item ${file.status}`;
            resultItem.innerHTML = `
                <div class="result-info">
                    <div class="result-status">${file.status === 'success' ? '✅' : '❌'}</div>
                    <div class="file-details">
                        <h4>${file.originalName}</h4>
                        <p>${file.status === 'success' ? `→ ${file.outputName}` : file.error}</p>
                    </div>
                </div>
                ${file.status === 'success' ? `
                    <div class="result-actions">
                        <button class="btn-secondary" onclick="app.downloadResult('${file.downloadUrl}', '${file.outputName}')">
                            Download
                        </button>
                    </div>
                ` : ''}
            `;
            fileResults.appendChild(resultItem);
        });

        resultsSection.classList.remove('hidden');
        this.showToast('Operation complete', `${successCount} files processed successfully`, 'success');
    }

    downloadResult(url, filename) {
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    cancelOperation() {
        if (this.currentOperation) {
            // TODO: Implement operation cancellation
            this.showToast('Operation cancelled', 'The operation has been cancelled', 'warning');
            this.hideProgressSection();
            this.currentOperation = null;
        }
    }

    resetToStart() {
        this.clearFiles();
        document.getElementById('resultsSection').classList.add('hidden');
        this.currentOperation = null;
    }

    // Modals
    async showConfigModal() {
        try {
            const response = await fetch('/api/v1/config');
            const config = await response.json();

            const configGrid = document.getElementById('configGrid');
            configGrid.innerHTML = '';

            Object.entries(config).forEach(([key, value]) => {
                const configItem = document.createElement('div');
                configItem.className = 'config-item';
                configItem.innerHTML = `
                    <span class="config-label">${this.formatConfigKey(key)}</span>
                    <span class="config-value">${this.formatConfigValue(value)}</span>
                `;
                configGrid.appendChild(configItem);
            });

            this.showModal('configModal');
        } catch (error) {
            this.showToast('Error', 'Failed to load configuration', 'error');
        }
    }

    async showStatusModal() {
        try {
            const response = await fetch('/api/v1/status');
            const status = await response.json();

            const statusGrid = document.getElementById('statusGrid');
            statusGrid.innerHTML = '';

            Object.entries(status).forEach(([key, value]) => {
                const statusItem = document.createElement('div');
                statusItem.className = 'status-item-modal';
                statusItem.innerHTML = `
                    <span class="status-label-modal">${this.formatConfigKey(key)}</span>
                    <span class="status-value-modal">${this.formatConfigValue(value)}</span>
                `;
                statusGrid.appendChild(statusItem);
            });

            this.showModal('statusModal');
        } catch (error) {
            this.showToast('Error', 'Failed to load server status', 'error');
        }
    }

    showModal(modalId) {
        document.getElementById('modalOverlay').classList.remove('hidden');
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
        document.getElementById(modalId).style.display = 'flex';
    }

    hideModal() {
        document.getElementById('modalOverlay').classList.add('hidden');
    }

    // Server status
    async loadServerStatus() {
        try {
            const response = await fetch('/api/v1/status');
            const status = await response.json();
            
            document.getElementById('serverVersion').textContent = status.version || 'Unknown';
        } catch (error) {
            console.error('Failed to load server status:', error);
        }
    }

    updateConnectionStatus(status) {
        const statusElement = document.getElementById('connectionStatus');
        statusElement.textContent = status;
        statusElement.className = `status-value ${status.toLowerCase()}`;
    }

    // Utility functions
    getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const iconMap = {
            'txt': '📄',
            'pdf': '📕',
            'doc': '📘',
            'docx': '📘',
            'xls': '📗',
            'xlsx': '📗',
            'ppt': '📙',
            'pptx': '📙',
            'jpg': '🖼️',
            'jpeg': '🖼️',
            'png': '🖼️',
            'gif': '🖼️',
            'mp4': '🎬',
            'avi': '🎬',
            'mp3': '🎵',
            'wav': '🎵',
            'zip': '📦',
            'rar': '📦',
            'enc': '🔒'
        };
        return iconMap[ext] || '📄';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatConfigKey(key) {
        return key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
    }

    formatConfigValue(value) {
        if (typeof value === 'boolean') {
            return value ? 'Yes' : 'No';
        }
        if (typeof value === 'number') {
            return value.toLocaleString();
        }
        return String(value);
    }

    // Toast notifications
    showToast(title, message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const iconMap = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };

        toast.innerHTML = `
            <div class="toast-icon">${iconMap[type]}</div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="btn-close" onclick="this.parentElement.remove()">×</button>
        `;

        toastContainer.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    }
}

// Initialize the application when DOM is loaded
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new FileEncryptorApp();
});
