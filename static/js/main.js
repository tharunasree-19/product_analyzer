// Global utility functions

// Show loading spinner
function showLoading(message = 'Processing...') {
    const existingLoader = document.getElementById('global-loader');
    if (existingLoader) {
        existingLoader.remove();
    }

    const loader = document.createElement('div');
    loader.id = 'global-loader';
    loader.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        z-index: 9999;
    `;
    
    loader.innerHTML = `
        <div class="spinner"></div>
        <div class="loading-text" style="color: white; font-size: 1.2rem; margin-top: 20px;">${message}</div>
    `;
    
    document.body.appendChild(loader);
}

// Hide loading spinner
function hideLoading() {
    const loader = document.getElementById('global-loader');
    if (loader) {
        loader.remove();
    }
}

// Show alert message
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        min-width: 300px;
        animation: slideInRight 0.3s ease-out;
    `;
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => alertDiv.remove(), 300);
    }, 5000);
}

// Handle form submission with JSON
async function submitForm(url, formData, method = 'POST') {
    try {
        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('Form submission error:', error);
        throw error;
    }
}

// Handle file upload with FormData
async function uploadFile(url, formData) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Upload failed');
        }
        
        return data;
    } catch (error) {
        console.error('File upload error:', error);
        throw error;
    }
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Get quality score class
function getQualityClass(score) {
    if (score >= 80) return 'quality-high';
    if (score >= 50) return 'quality-medium';
    return 'quality-low';
}

// Image preview handler
function handleImagePreview(input, previewElement) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        
        reader.onload = function(e) {
            previewElement.innerHTML = `
                <img src="${e.target.result}" alt="Preview" style="max-width: 100%; max-height: 400px; border-radius: 12px;">
            `;
            previewElement.style.display = 'block';
        };
        
        reader.readAsDataURL(input.files[0]);
    }
}

// Validate file size and type
function validateFile(file, maxSizeMB = 16) {
    const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg'];
    
    if (!allowedTypes.includes(file.type)) {
        throw new Error('Invalid file type. Please upload PNG, JPG, or JPEG images.');
    }
    
    const maxSize = maxSizeMB * 1024 * 1024;
    if (file.size > maxSize) {
        throw new Error(`File size exceeds ${maxSizeMB}MB limit.`);
    }
    
    return true;
}

// Logout function
async function logout() {
    if (confirm('Are you sure you want to logout?')) {
        showLoading('Logging out...');
        try {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/';
        } catch (error) {
            console.error('Logout error:', error);
            window.location.href = '/';
        }
    }
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Auto-hide flash messages
document.addEventListener('DOMContentLoaded', () => {
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(alert => {
        setTimeout(() => {
            alert.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
});

// Confirm before leaving page with unsaved changes
let hasUnsavedChanges = false;

window.addEventListener('beforeunload', (e) => {
    if (hasUnsavedChanges) {
        e.preventDefault();
        e.returnValue = '';
    }
});

// Mark form as changed
function markFormChanged() {
    hasUnsavedChanges = true;
}

// Mark form as saved
function markFormSaved() {
    hasUnsavedChanges = false;
}

// Export functions for use in other scripts
window.appUtils = {
    showLoading,
    hideLoading,
    showAlert,
    submitForm,
    uploadFile,
    formatDate,
    getQualityClass,
    handleImagePreview,
    validateFile,
    logout,
    markFormChanged,
    markFormSaved
};