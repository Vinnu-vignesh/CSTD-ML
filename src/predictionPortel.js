// src/predictionPortel.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';


const FLASK_API_URL = 'http://127.0.0.1:5000/api/predict';
const FILES_API_URL = 'http://127.0.0.1:5000/api/files';
const FILE_DOWNLOAD_BASE_URL = 'http://127.0.0.1:5000/api/files';

const USERS_KEY = 'cstd_users';
const CURRENT_USER_KEY = 'cstd_current_user';
const CURRENT_ROLE_KEY = 'cstd_current_role';

// ---------------- LOADER ----------------
const SimpleLoader = () => (
    <div style={loaderStyles.container}>
        <div style={loaderStyles.spinner}></div>
        <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
    </div>
);

const loaderStyles = {
    container: { display: 'flex', justifyContent: 'center', alignItems: 'center', margin: '20px auto' },
    spinner: {
        border: '4px solid #374151',
        borderTop: '4px solid #10b981',
        borderRadius: '50%',
        width: '30px',
        height: '30px',
        animation: 'spin 1s linear infinite',
    }
};

// ---------------- LOCALSTORAGE HELPERS ----------------
const loadUsersFromStorage = () => {
    try {
        const raw = localStorage.getItem(USERS_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
};

const saveUsersToStorage = (users) => {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
};

const hashPassword = (password) => {
    return CryptoJS.SHA256(password).toString();
    // If you want MD5 instead:
    // return CryptoJS.MD5(password).toString();
};


// ---------------- AUTH MODAL ----------------
const AuthModal = ({ isOpen, mode, onClose, onLoginSuccess, setMode }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('user');
    const [message, setMessage] = useState('');

    useEffect(() => {
        if (isOpen) {
            setUsername('');
            setPassword('');
            setRole('user');
            setMessage('');
        }
    }, [isOpen, mode]);

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        setMessage('');

        if (!username.trim() || !password.trim()) {
            setMessage('Please enter both username and password.');
            return;
        }

        // ========== REGISTER ==========
        if (mode === 'register') {
            const users = loadUsersFromStorage();
            const exists = users.some(u => u.username === username.trim());
            if (exists) {
                setMessage('Username already exists. Please choose another one.');
                return;
            }

            const newUser = {
                username: username.trim(),
                password: hashPassword(password.trim()),
                role,
            };

            saveUsersToStorage([...users, newUser]);
            setMessage('Registration successful! You can now login.');
            setMode('login');
            setPassword('');
            return;
        }

        // ========== FORGOT PASSWORD ==========
        if (mode === 'forgot') {
            const users = loadUsersFromStorage();
            const idx = users.findIndex(u => u.username === username.trim());

            if (idx === -1) {
                setMessage('User not found. Please check the username.');
                return;
            }

            // Update password
            users[idx] = {
                ...users[idx],
                password: hashPassword(password.trim()),
            };

            saveUsersToStorage(users);

            setMessage('Password reset successful! You can now login with your new password.');
            setMode('login');
            setPassword('');
            return;
        }

        // ========== LOGIN ==========
        const users = loadUsersFromStorage();
        const hashedInputPassword = hashPassword(password.trim());

        const user = users.find(
            u =>
                u.username === username.trim() &&
                u.password === hashedInputPassword
        );

        if (!user) {
            setMessage('Access Denied!.');
            return;
        }

        localStorage.setItem(CURRENT_USER_KEY, user.username);
        localStorage.setItem(CURRENT_ROLE_KEY, user.role);

        onLoginSuccess(user);
        onClose();
    };

    const isLogin = mode === 'login';
    const isRegister = mode === 'register';
    const isForgot = mode === 'forgot';

    return (
        <div style={modalStyles.backdrop}>
            <div style={modalStyles.card}>
                <div style={modalStyles.headerRow}>
                    <h2 style={modalStyles.title}>
                        {isLogin && 'Login to CSTD Analyzer'}
                        {isRegister && 'Create an Account'}
                        {isForgot && 'Reset your Password'}
                    </h2>
                    <button onClick={onClose} style={modalStyles.closeButton}>✕</button>
                </div>

                <div style={modalStyles.tabRow}>
                    <button
                        onClick={() => setMode('login')}
                        style={isLogin ? modalStyles.tabActive : modalStyles.tab}
                    >
                        Login
                    </button>
                    <button
                        onClick={() => setMode('register')}
                        style={isRegister ? modalStyles.tabActive : modalStyles.tab}
                    >
                        Register
                    </button>
                </div>

                <form onSubmit={handleSubmit} style={modalStyles.form}>
                    <label style={modalStyles.label}>
                        Username
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            style={modalStyles.input}
                        />
                    </label>

                    <label style={modalStyles.label}>
                        {isForgot ? 'New Password' : 'Password'}
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            style={modalStyles.input}
                        />
                    </label>

                    {/* Role selection only for register */}
                    {isRegister && (
                        <label style={modalStyles.label}>
                            Role
                            <select
                                value={role}
                                onChange={(e) => setRole(e.target.value)}
                                style={modalStyles.input}
                            >
                                <option value="user">User</option>
                                <option value="admin">Admin</option>
                            </select>
                        </label>
                    )}

                    {message && (
                        <div style={modalStyles.messageBox}>
                            {message}
                        </div>
                    )}

                    <button type="submit" style={modalStyles.submitButton}>
                        {isLogin && 'Login'}
                        {isRegister && 'Register'}
                        {isForgot && 'Reset Password'}
                    </button>

                    {/* Forgot password link only visible in login mode */}
                    {isLogin && (
                        <div style={modalStyles.note}>
                            <button
                                type="button"
                                onClick={() => setMode('forgot')}
                                style={{
                                    border: 'none',
                                    background: 'transparent',
                                    color: '#60a5fa',
                                    cursor: 'pointer',
                                    fontSize: '0.75rem',
                                    textDecoration: 'underline',
                                    padding: 0,
                                    marginTop: '4px',
                                }}
                            >
                                Forgot password?
                            </button>
                        </div>
                    )}
                </form>
            </div>
        </div>
    );
};


// ---------------- PUBLIC HOME VIEW ----------------
const HomeView = ({ onStartAnalysis, isLoggedIn }) => (
    <div style={homeStyles.container}>
        <h1 style={homeStyles.title}>Cyber Security Threat Analyzer</h1>
        <p style={homeStyles.subtitle}>
            A web-based system that uses Machine Learning to classify network traffic as benign or malicious
            using your uploaded CSV logs.
        </p>

        <div style={homeStyles.actionsRow}>
            <button
                onClick={onStartAnalysis}
                style={homeStyles.buttonPrimary}
            >
                {isLoggedIn ? 'Go to Analysis Portal' : 'Login to Start Analysis'}
            </button>
        </div>

        <div style={homeStyles.statBar}>
            <div style={homeStyles.statItem}>
                <span style={homeStyles.statValue}>ML Powered</span>
                <span style={homeStyles.statLabel}>Random Forest Classifier</span>
            </div>
            <div style={homeStyles.statItem}>
                <span style={homeStyles.statValue}>Batch CSV</span>
                <span style={homeStyles.statLabel}>Upload & Analyze Logs</span>
            </div>
            <div style={homeStyles.statItem}>
                <span style={homeStyles.statValue}>Result CSV</span>
                <span style={homeStyles.statLabel}>Predicted Labels Added</span>
            </div>
        </div>
    </div>
);

// ---------------- PREDICTION VIEW ----------------
const PredictionView = ({ role }) => {
    const [selectedFile, setSelectedFile] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [message, setMessage] = useState('Ready to analyze data. Please upload a network traffic CSV file.');
    const [isError, setIsError] = useState(false);
    const [stats, setStats] = useState(null);

    const handleFileChange = (event) => {
        setIsError(false);
        setStats(null);
        const file = event.target.files[0];
        if (file && file.name.endsWith('.csv')) {
            setSelectedFile(file);
            setMessage(`File selected: ${file.name}`);
        } else {
            setSelectedFile(null);
            setMessage('Error: Please select a valid CSV file.');
            setIsError(true);
        }
    };

    const handleFileUpload = async () => {
        if (!selectedFile || isLoading) return;

        const formData = new FormData();
        formData.append('file', selectedFile);

        setIsLoading(true);
        setIsError(false);
        setStats(null);
        setMessage('Analyzing data... This may take a moment.');

        try {
            const response = await axios.post(FLASK_API_URL, formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
                responseType: 'blob',
            });

            let filename = 'classified_packets.csv';
            const contentDisposition = response.headers['content-disposition'];
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="?(.+)"?$/);
                if (filenameMatch && filenameMatch[1]) { filename = filenameMatch[1]; }
            }

            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);

            setMessage(`Analysis complete! Classified file downloaded. Filename: ${filename}`);
            setStats({ processed: true, filename: filename });

        } catch (error) {
            let errorMessage = 'An unknown network or server error occurred.';
            if (error.code === 'ERR_NETWORK') {
                errorMessage = 'Network Error: Cannot connect to Flask backend. Is the server running on http://127.0.0.1:5000?';
            } else if (error.response) {
                const errorBlob = error.response.data;
                const errorText = await new Promise(resolve => {
                    const reader = new FileReader();
                    reader.onload = () => resolve(reader.result);
                    reader.readAsText(errorBlob);
                });

                try {
                    const errorJson = JSON.parse(errorText);
                    errorMessage = errorJson.error || errorMessage;
                } catch {
                    errorMessage = `HTTP Error ${error.response.status}: ${error.response.statusText}. Check server console.`;
                }
            }

            setMessage(`Prediction Failed: ${errorMessage}`);
            setIsError(true);
            console.error('API Error:', error);
        } finally {
            setIsLoading(false);
            setSelectedFile(null);
            const input = document.getElementById('file-upload-input');
            if (input) input.value = '';
        }
    };

    return (
        <div style={predictStyles.card}>
            <h2 style={predictStyles.title}>Batch Threat Analysis Portal</h2>
            <p style={predictStyles.subtitle}>
                Upload your network traffic log (CSV) for ML-driven classification.
                {role === 'admin' && ' As an ADMIN, you can manage and review all classified outputs.'}
            </p>

            <div
                style={{
                    ...predictStyles.messageBox,
                    color: isError ? '#f87171' : '#10b981',
                    borderColor: isError ? '#f87171' : '#10b981',
                }}
            >
                {message}
            </div>

            <label htmlFor="file-upload-input" style={predictStyles.fileInputLabel}>
                <input
                    type="file"
                    id="file-upload-input"
                    accept=".csv"
                    onChange={handleFileChange}
                    style={{ display: 'none' }}
                    disabled={isLoading}
                />
                <span style={predictStyles.fileInputText}>
                    {selectedFile ? `File Selected: ${selectedFile.name}` : 'Click to Select CSV File'}
                </span>
            </label>

            <button
                onClick={handleFileUpload}
                disabled={!selectedFile || isLoading || isError}
                style={{
                    ...predictStyles.button,
                    backgroundColor: (isLoading || !selectedFile || isError) ? '#374151' : '#10b981',
                    cursor: (isLoading || !selectedFile || isError) ? 'not-allowed' : 'pointer',
                    boxShadow: (isLoading || !selectedFile || isError) ? 'none' : '0 4px 10px rgba(16, 185, 129, 0.4)',
                }}
            >
                {isLoading ? 'PROCESSING...' : 'RUN PREDICTION'}
            </button>

            {isLoading && <SimpleLoader />}

            {stats && (
                <div style={predictStyles.statsBox}>
                    <h3 style={predictStyles.statsTitle}>Analysis Complete!</h3>
                    <p>File <strong>{stats.filename}</strong> was processed successfully.</p>
                    <p style={predictStyles.downloadHint}>The classified CSV file was generated and downloaded.</p>
                </div>
            )}
        </div>
    );
};

// ---------------- ADMIN FILES VIEW (ADMIN ONLY) ----------------
const AdminFilesView = () => {
    const [files, setFiles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                setLoading(true);
                setError('');
                const res = await axios.get(FILES_API_URL);
                setFiles(res.data.files || []);
            } catch (err) {
                console.error(err);
                setError('Failed to load files. Make sure Flask server is running and saving outputs.');
            } finally {
                setLoading(false);
            }
        };

        fetchFiles();
    }, []);

    return (
        <div style={adminStyles.card}>
            <h2 style={adminStyles.title}>Classified CSV Files (Admin)</h2>
            <p style={adminStyles.subtitle}>
                These are the classified CSV outputs saved by the server after each analysis run.
            </p>

            {loading && <p style={adminStyles.infoText}>Loading files...</p>}
            {error && <p style={{ ...adminStyles.infoText, color: '#f87171' }}>{error}</p>}

            {!loading && !error && files.length === 0 && (
                <p style={adminStyles.infoText}>No classified files found yet.</p>
            )}

            {!loading && !error && files.length > 0 && (
                <table style={adminStyles.table}>
                    <thead>
                        <tr>
                            <th style={adminStyles.th}><pre>       #</pre></th>
                            <th style={adminStyles.th}><pre>                Filename</pre></th>
                            <th style={adminStyles.th}><pre>          Action</pre></th>
                        </tr>
                    </thead>
                    <tbody>
                        {files.map((name, idx) => (
                            <tr key={name} style={adminStyles.tr}>
                                <td style={adminStyles.td}>{idx + 1}</td>
                                <td style={adminStyles.td}>{name}</td>
                                <td style={adminStyles.td}>
                                    <a
                                        href={`${FILE_DOWNLOAD_BASE_URL}/${encodeURIComponent(name)}`}
                                        style={adminStyles.downloadLink}
                                    >
                                        Download
                                    </a>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
};

// ---------------- ROOT APP COMPONENT ----------------
function App() {
    const [view, setView] = useState('home'); // 'home' | 'predict' | 'admin_files'
    const [currentUser, setCurrentUser] = useState(null);
    const [role, setRole] = useState(null);
    const [authOpen, setAuthOpen] = useState(false);
    const [authMode, setAuthMode] = useState('login'); // 'login' | 'register'

    useEffect(() => {
        const storedUser = localStorage.getItem(CURRENT_USER_KEY);
        const storedRole = localStorage.getItem(CURRENT_ROLE_KEY);
        if (storedUser && storedRole) {
            setCurrentUser(storedUser);
            setRole(storedRole);
        }
    }, []);

    const openAuth = (mode) => {
        setAuthMode(mode);
        setAuthOpen(true);
    };

    const handleLoginSuccess = (user) => {
        setCurrentUser(user.username);
        setRole(user.role);
        setView('predict');
    };

    const handleLogout = () => {
        setCurrentUser(null);
        setRole(null);
        localStorage.removeItem(CURRENT_USER_KEY);
        localStorage.removeItem(CURRENT_ROLE_KEY);
        setView('home');
    };

    const handleStartAnalysis = () => {
        if (!currentUser) {
            openAuth('login');
        } else {
            setView('predict');
        }
    };

    const handleNavClick = (targetView) => {
        if (targetView === 'predict' && !currentUser) {
            openAuth('login');
            return;
        }
        if (targetView === 'admin_files') {
            if (!currentUser) {
                openAuth('login');
                return;
            }
            if (role !== 'admin') {
                alert('Only admin can access this section.');
                return;
            }
        }
        setView(targetView);
    };

    const renderView = () => {
        if (view === 'predict' && currentUser) {
            return <PredictionView role={role} />;
        }
        if (view === 'admin_files' && currentUser && role === 'admin') {
            return <AdminFilesView />;
        }
        return (
            <HomeView
                onStartAnalysis={handleStartAnalysis}
                isLoggedIn={!!currentUser}
            />
        );
    };

    return (
        <div style={styles.container}>
            <style>{`
                body { background-color: #0d131f; color: #e5e7eb; font-family: 'Inter', sans-serif; }
            `}</style>

            <header style={styles.header}>
                <div style={styles.logo}>🛡️ CSTD Analyzer</div>

                <nav style={styles.nav}>
                    <button
                        onClick={() => handleNavClick('home')}
                        style={view === 'home' ? styles.navButtonActive : styles.navButton}
                    >
                        Home
                    </button>
                    <button
                        onClick={() => handleNavClick('predict')}
                        style={view === 'predict' ? styles.navButtonActive : styles.navButton}
                    >
                        Analyze Data
                    </button>
                    {currentUser && role === 'admin' && (
                        <button
                            onClick={() => handleNavClick('admin_files')}
                            style={view === 'admin_files' ? styles.navButtonActive : styles.navButton}
                        >
                            Admin Files
                        </button>
                    )}
                </nav>

                <div style={styles.userSection}>
                    {currentUser ? (
                        <>
                            <span style={styles.userText}>
                                {currentUser} ({role})
                            </span>
                            <button onClick={handleLogout} style={styles.logoutButton}>
                                Logout
                            </button>
                        </>
                    ) : (
                        <>
                            <button
                                onClick={() => openAuth('login')}
                                style={styles.authButton}
                            >
                                Login
                            </button>
                            <button
                                onClick={() => openAuth('register')}
                                style={styles.authButtonOutline}
                            >
                                Register
                            </button>
                        </>
                    )}
                </div>
            </header>

            {currentUser && role === 'admin' && (
                <div style={styles.adminBanner}>
                    Logged in as <strong>ADMIN</strong>. You can view all classified CSV results.
                </div>
            )}

            <main style={styles.mainContent}>
                {renderView()}
            </main>

            <AuthModal
                isOpen={authOpen}
                mode={authMode}
                onClose={() => setAuthOpen(false)}
                onLoginSuccess={handleLoginSuccess}
                setMode={setAuthMode}
            />
        </div>
    );
}

export default App;

// ---------------- STYLES ----------------
const styles = {
    container: {
        fontFamily: 'Inter, system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
        minHeight: '100vh',
        background: 'radial-gradient(circle at top, #1f2937 0, #020617 55%, #000 100%)',
        color: '#e5e7eb',
    },
    header: {
        position: 'sticky',
        top: 0,
        zIndex: 20,
        backdropFilter: 'blur(14px)',
        backgroundColor: 'rgba(15, 23, 42, 0.92)',
        padding: '12px 32px',
        borderBottom: '1px solid rgba(148,163,184,0.25)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '16px',
    },
    logo: {
        fontSize: '1.5rem',
        fontWeight: '800',
        color: '#e5e7eb',
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
    nav: {
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        padding: '4px',
        borderRadius: '999px',
        backgroundColor: 'rgba(15,23,42,0.9)',
        border: '1px solid rgba(148,163,184,0.35)',
    },
    navButton: {
        backgroundColor: 'transparent',
        color: '#9ca3af',
        border: 'none',
        padding: '6px 14px',
        fontSize: '0.9rem',
        cursor: 'pointer',
        borderRadius: '999px',
    },
    navButtonActive: {
        backgroundColor: '#2563eb',
        color: '#f9fafb',
        border: 'none',
        padding: '6px 14px',
        fontSize: '0.9rem',
        cursor: 'pointer',
        borderRadius: '999px',
        fontWeight: '600',
    },
    mainContent: {
        padding: '40px 16px 60px',
    },
    userSection: {
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
    },
    authButton: {
        borderRadius: '999px',
        border: 'none',
        padding: '6px 14px',
        backgroundColor: '#2563eb',
        color: '#f9fafb',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: '600',
    },
    authButtonOutline: {
        borderRadius: '999px',
        padding: '6px 14px',
        backgroundColor: 'transparent',
        border: '1px solid rgba(148,163,184,0.7)',
        color: '#e5e7eb',
        cursor: 'pointer',
        fontSize: '0.85rem',
    },
    userText: {
        color: '#e5e7eb',
        fontSize: '0.85rem',
        opacity: 0.9,
    },
    logoutButton: {
        border: 'none',
        borderRadius: '999px',
        padding: '5px 12px',
        backgroundColor: '#ef4444',
        color: '#f9fafb',
        cursor: 'pointer',
        fontSize: '0.8rem',
    },
    adminBanner: {
        margin: '16px auto 0',
        maxWidth: '960px',
        padding: '10px 14px',
        borderRadius: '999px',
        backgroundColor: 'rgba(251,191,36,0.08)',
        borderLeft: '4px solid rgba(250,204,21,0.6)',
        fontSize: '0.85rem',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
};

const homeStyles = {
    container: {
        textAlign: 'center',
        padding: '70px 20px 40px',
        maxWidth: '950px',
        margin: '0 auto',
    },
    title: {
        fontSize: '3rem',
        fontWeight: '900',
        color: '#f9fafb',
        marginBottom: '16px',
    },
    subtitle: {
        fontSize: '1rem',
        color: '#9ca3af',
        marginBottom: '32px',
        lineHeight: 1.7,
        maxWidth: '720px',
        marginLeft: 'auto',
        marginRight: 'auto',
    },
    actionsRow: {
        marginBottom: '36px',
    },
    buttonPrimary: {
        backgroundColor: '#2563eb',
        color: '#f9fafb',
        padding: '13px 32px',
        fontSize: '1rem',
        fontWeight: '700',
        border: 'none',
        borderRadius: '999px',
        cursor: 'pointer',
    },
    statBar: {
        marginTop: '40px',
        display: 'flex',
        justifyContent: 'space-between',
        backgroundColor: 'rgba(15,23,42,0.8)',
        padding: '18px 22px',
        borderRadius: '18px',
        border: '1px solid rgba(75,85,99,0.9)',
        flexWrap: 'wrap',
        gap: '12px',
    },
    statItem: {
        textAlign: 'left',
        minWidth: '170px',
    },
    statValue: {
        display: 'block',
        fontSize: '1.15rem',
        fontWeight: '700',
        color: '#e5e7eb',
        marginBottom: '3px',
    },
    statLabel: {
        display: 'block',
        fontSize: '0.78rem',
        color: '#9ca3af',
        textTransform: 'uppercase',
    },
};

const predictStyles = {
    card: {
        padding: '32px 26px',
        maxWidth: '580px',
        margin: '10px auto 0',
        backgroundColor: 'rgba(15,23,42,0.95)',
        borderRadius: '18px',
        textAlign: 'center',
        border: '1px solid rgba(75,85,99,0.9)',
    },
    title: {
        fontSize: '1.6rem',
        fontWeight: '700',
        color: '#f9fafb',
        marginBottom: '6px',
    },
    subtitle: {
        fontSize: '0.9rem',
        color: '#9ca3af',
        marginBottom: '24px',
    },
    messageBox: {
        minHeight: '40px',
        padding: '12px 14px',
        marginBottom: '18px',
        borderRadius: '12px',
        fontWeight: '500',
        fontSize: '0.85rem',
        border: '1px solid #4b5563',
        backgroundColor: 'rgba(15,23,42,0.9)',
    },
    fileInputLabel: {
        display: 'block',
        padding: '14px 18px',
        borderRadius: '12px',
        backgroundColor: 'rgba(15,23,42,0.95)',
        border: '1px dashed rgba(148,163,184,0.5)',
        color: '#e5e7eb',
        cursor: 'pointer',
        textAlign: 'center',
        marginBottom: '16px',
        fontSize: '0.9rem',
    },
    fileInputText: {
        fontWeight: '500',
        fontSize: '0.95rem',
    },
    button: {
        padding: '12px 26px',
        fontSize: '1rem',
        color: '#f9fafb',
        border: 'none',
        borderRadius: '999px',
        marginTop: '10px',
        fontWeight: '700',
        backgroundColor: '#2563eb',
    },
    statsBox: {
        marginTop: '22px',
        padding: '16px 18px',
        backgroundColor: '#111827',
        borderRadius: '14px',
        textAlign: 'left',
        borderLeft: '3px solid #2563eb',
        fontSize: '0.85rem',
        color: '#e5e7eb',
    },
    statsTitle: {
        fontSize: '1rem',
        marginBottom: '8px',
        color: '#e5e7eb',
    },
    downloadHint: {
        marginTop: '6px',
        fontStyle: 'italic',
        color: '#9ca3af',
    },
};

const modalStyles = {
    backdrop: {
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(15,23,42,0.8)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        backdropFilter: 'blur(6px)',
    },
    card: {
        width: '100%',
        maxWidth: '380px',
        backgroundColor: '#111827',
        borderRadius: '18px',
        padding: '22px 20px',
        border: '1px solid rgba(75,85,99,0.7)',
    },
    headerRow: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '10px',
    },
    title: {
        fontSize: '1.1rem',
        fontWeight: '700',
        color: '#f9fafb',
    },
    closeButton: {
        border: 'none',
        background: 'transparent',
        color: '#9ca3af',
        fontSize: '1rem',
        cursor: 'pointer',
    },
    tabRow: {
        display: 'flex',
        marginBottom: '14px',
        borderRadius: '999px',
        backgroundColor: '#1f2937',
        padding: '2px',
        border: '1px solid #374151',
    },
    tab: {
        flex: 1,
        padding: '6px 0',
        borderRadius: '999px',
        border: 'none',
        background: 'transparent',
        color: '#9ca3af',
        cursor: 'pointer',
        fontSize: '0.8rem',
    },
    tabActive: {
        flex: 1,
        padding: '6px 0',
        borderRadius: '999px',
        border: 'none',
        backgroundColor: '#2563eb',
        color: '#f9fafb',
        cursor: 'pointer',
        fontSize: '0.8rem',
        fontWeight: '600',
    },
    form: {
        display: 'flex',
        flexDirection: 'column',
        gap: '9px',
        marginBottom: '6px',
    },
    label: {
        fontSize: '0.78rem',
        color: '#d1d5db',
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
    },
    input: {
        padding: '7px 9px',
        borderRadius: '8px',
        border: '1px solid #4b5563',
        backgroundColor: '#1f2937',
        color: '#e5e7eb',
        fontSize: '0.82rem',
    },
    messageBox: {
        marginTop: '3px',
        padding: '6px 8px',
        borderRadius: '6px',
        backgroundColor: '#1f2937',
        fontSize: '0.75rem',
        color: '#e5e7eb',
    },
    submitButton: {
        marginTop: '6px',
        padding: '8px 0',
        borderRadius: '999px',
        border: 'none',
        backgroundColor: '#2563eb',
        color: '#f9fafb',
        fontWeight: '700',
        fontSize: '0.9rem',
        cursor: 'pointer',
    },
    note: {
        marginTop: '6px',
        fontSize: '0.7rem',
        color: '#9ca3af',
        textAlign: 'center',
    },
};

const adminStyles = {
    card: {
        padding: '26px 24px',
        maxWidth: '760px',
        margin: '10px auto 0',
        backgroundColor: '#111827',
        borderRadius: '18px',
        border: '1px solid #374151',
    },
    title: {
        fontSize: '1.4rem',
        fontWeight: '700',
        marginBottom: '4px',
        color: '#f9fafb',
    },
    subtitle: {
        fontSize: '0.9rem',
        color: '#9ca3af',
        marginBottom: '18px',
    },
    infoText: {
        fontSize: '0.9rem',
        color: '#e5e7eb',
    },
    table: {
        width: '100%',
        borderCollapse: 'collapse',
        marginTop: '10px',
        fontSize: '0.9rem',
    },
    th: {
        textAlign: 'left',
        padding: '8px',
        borderBottom: '1px solid #374151',
        color: '#9ca3af',
        fontWeight: '500',
    },
    tr: {
        borderBottom: '1px solid #1f2937',
    },
    td: {
        padding: '8px',
        color: '#e5e7eb',
    },
    downloadLink: {
        padding: '5px 12px',
        borderRadius: '999px',
        backgroundColor: '#2563eb',
        color: '#f9fafb',
        textDecoration: 'none',
        fontWeight: '600',
        fontSize: '0.8rem',
    },
};
