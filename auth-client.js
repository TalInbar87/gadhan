/**
 * Secure Authentication Client Library
 * Use this in your HTML files
 */

 class SecureAuthClient {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
        this.token = this.getStoredToken();
        this.user = this.getStoredUser();
    }
    
    // ============================================================
    // STORAGE MANAGEMENT
    // ============================================================
    
    getStoredToken() {
        return sessionStorage.getItem('auth_token');
    }
    
    setStoredToken(token) {
        sessionStorage.setItem('auth_token', token);
        this.token = token;
    }
    
    getStoredUser() {
        const userStr = sessionStorage.getItem('auth_user');
        return userStr ? JSON.parse(userStr) : null;
    }
    
    setStoredUser(user) {
        sessionStorage.setItem('auth_user', JSON.stringify(user));
        this.user = user;
    }
    
    clearAuth() {
        sessionStorage.removeItem('auth_token');
        sessionStorage.removeItem('auth_user');
        this.token = null;
        this.user = null;
    }
    
    // ============================================================
    // AUTHENTICATION
    // ============================================================
    
    async login(username, password) {
        try {
            // Use form data to bypass CORS
            const formData = new URLSearchParams();
            formData.append('data', JSON.stringify({
                action: 'login',
                username: username,
                password: password
            }));
            
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.statusCode === 200 && result.data) {
                this.setStoredToken(result.data.token);
                this.setStoredUser(result.data.user);
                return { success: true, user: result.data.user };
            } else {
                return { success: false, error: result.message };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: 'שגיאת רשת - ודא שה-URL של Google Apps Script נכון' };
        }
    }
    
    async logout() {
        this.clearAuth();
        window.location.href = 'login.html';
    }
    
    async verifyToken() {
        if (!this.token) {
            return false;
        }
        
        try {
            const formData = new URLSearchParams();
            formData.append('data', JSON.stringify({
                action: 'verify_token',
                token: this.token
            }));
            
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            return result.statusCode === 200;
        } catch (error) {
            console.error('Token verification error:', error);
            return false;
        }
    }
    
    isAuthenticated() {
        return this.token !== null && this.user !== null;
    }
    
    hasPermission(permission) {
        if (!this.user || !this.user.permissions) {
            return false;
        }
        return this.user.permissions.includes(permission);
    }
    
    // ============================================================
    // ENCRYPTION UTILITIES
    // ============================================================
    
    async encryptData(data, key) {
        // Simple XOR encryption - matching backend
        const jsonStr = JSON.stringify(data);
        let encrypted = '';
        
        for (let i = 0; i < jsonStr.length; i++) {
            encrypted += String.fromCharCode(
                jsonStr.charCodeAt(i) ^ key.charCodeAt(i % key.length)
            );
        }
        
        // Use Unicode-safe base64 encoding
        return this.unicodeTob64(encrypted);
    }
    
    async decryptData(encryptedData, key) {
        // Use Unicode-safe base64 decoding
        const decoded = this.b64ToUnicode(encryptedData);
        let decrypted = '';
        
        for (let i = 0; i < decoded.length; i++) {
            decrypted += String.fromCharCode(
                decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length)
            );
        }
        
        return JSON.parse(decrypted);
    }
    
    // Unicode-safe base64 encoding
    unicodeTob64(str) {
        return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => {
            return String.fromCharCode(parseInt(p1, 16));
        }));
    }
    
    // Unicode-safe base64 decoding
    b64ToUnicode(b64) {
        return decodeURIComponent(Array.prototype.map.call(atob(b64), (c) => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    }
    
    // ============================================================
    // DATA OPERATIONS
    // ============================================================
    
    async submitData(formData, formType) {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }
        
        try {
            // Encrypt form data
            const encryptedData = await this.encryptData(formData, this.token);
            
            const postData = new URLSearchParams();
            postData.append('data', JSON.stringify({
                action: 'submit_data',
                token: this.token,
                formData: encryptedData,
                formType: formType
            }));
            
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                body: postData
            });
            
            const result = await response.json();
            
            if (result.statusCode === 401) {
                this.clearAuth();
                window.location.href = 'login.html';
                throw new Error('Session expired');
            }
            
            if (result.statusCode === 403) {
                throw new Error('Insufficient permissions');
            }
            
            if (result.statusCode === 200) {
                return { success: true, data: result.data };
            } else {
                throw new Error(result.message);
            }
        } catch (error) {
            console.error('Submit error:', error);
            throw error;
        }
    }
    
    async getExistingData(personalNumber, formType) {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }
        
        try {
            const postData = new URLSearchParams();
            postData.append('data', JSON.stringify({
                action: 'get_existing',
                token: this.token,
                personalNumber: personalNumber,
                formType: formType
            }));
            
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                body: postData
            });
            
            const result = await response.json();
            
            if (result.statusCode === 401) {
                this.clearAuth();
                window.location.href = 'login.html';
                throw new Error('Session expired');
            }
            
            if (result.statusCode === 403) {
                throw new Error('Insufficient permissions');
            }
            
            if (result.statusCode === 200 && result.data) {
                // Decrypt data
                const decryptedData = await this.decryptData(result.data.data, this.token);
                return { success: true, data: decryptedData };
            } else if (result.statusCode === 404) {
                return { success: true, data: null };
            } else {
                throw new Error(result.message);
            }
        } catch (error) {
            console.error('Get existing error:', error);
            throw error;
        }
    }
    
    // ============================================================
    // USER MANAGEMENT (Admin only)
    // ============================================================
    
    async createUser(userData) {
        if (!this.isAuthenticated() || !this.hasPermission('manage_users')) {
            throw new Error('Insufficient permissions');
        }
        
        try {
            const postData = new URLSearchParams();
            postData.append('data', JSON.stringify({
                action: 'create_user',
                token: this.token,
                userData: userData
            }));
            
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                body: postData
            });
            
            const result = await response.json();
            
            if (result.statusCode === 200) {
                return { success: true };
            } else {
                throw new Error(result.message);
            }
        } catch (error) {
            console.error('Create user error:', error);
            throw error;
        }
    }
}

// ============================================================
// AUTH GUARD - Use this in your pages
// ============================================================

class AuthGuard {
    constructor(authClient, requiredPermission = null) {
        this.authClient = authClient;
        this.requiredPermission = requiredPermission;
    }
    
    async checkAuth() {
        if (!this.authClient.isAuthenticated()) {
            this.redirectToLogin();
            return false;
        }
        
        const isValid = await this.authClient.verifyToken();
        if (!isValid) {
            this.authClient.clearAuth();
            this.redirectToLogin();
            return false;
        }
        
        if (this.requiredPermission && !this.authClient.hasPermission(this.requiredPermission)) {
            this.showAccessDenied();
            return false;
        }
        
        return true;
    }
    
    redirectToLogin() {
        // Get just the filename, not the full path
        const currentPage = window.location.pathname.split('/').pop() || 'index-secure.html';
        window.location.href = `login.html?redirect=${encodeURIComponent(currentPage)}`;
    }
    
    showAccessDenied() {
        document.body.innerHTML = `
            <div style="display: flex; justify-content: center; align-items: center; height: 100vh; background: #f3f4f6;">
                <div style="text-align: center; padding: 2rem; background: white; border-radius: 1rem; box-shadow: 0 10px 25px rgba(0,0,0,0.1);">
                    <h1 style="color: #ef4444; font-size: 3rem; margin-bottom: 1rem;">🚫</h1>
                    <h2 style="color: #1f2937; margin-bottom: 0.5rem;">אין הרשאה</h2>
                    <p style="color: #6b7280; margin-bottom: 1.5rem;">אין לך הרשאה לגשת לדף זה</p>
                    <button onclick="window.location.href='index.html'" 
                            style="padding: 0.75rem 1.5rem; background: #3b82f6; color: white; border: none; border-radius: 0.5rem; cursor: pointer; font-size: 1rem;">
                        חזרה לדף הבית
                    </button>
                </div>
            </div>
        `;
    }
}