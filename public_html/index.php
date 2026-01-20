<?php
require_once 'app.php';

$isLoggedIn = isLoggedIn();
$userType = getUserType();

$csrfToken = generateCSRFToken('main');
$_SESSION['csrf_token_main'] = $csrfToken;
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>AI Assistant</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary: #64748b;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --dark: #1e293b;
            --light: #f8fafc;
            --gray: #94a3b8;
            --text: #0f172a;
            --text-light: #64748b;
            --border: #e2e8f0;
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --radius: 0.75rem;
            --transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html {
            font-size: 16px;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--light);
            color: var(--text);
            line-height: 1.5;
            overflow-x: hidden;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .app-container {
            display: flex;
            flex-direction: column;
            height: 100vh;
            width: 100%;
            max-width: 100%;
            margin: 0 auto;
            background: white;
            box-shadow: var(--shadow);
        }

        @media (min-width: 768px) {
            .app-container {
                max-width: 768px;
            }
        }

        @media (min-width: 1024px) {
            .app-container {
                max-width: 1024px;
            }
        }

        .header {
            background: var(--primary);
            color: white;
            padding: 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-title {
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .header-actions {
            display: flex;
            gap: 0.5rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: var(--radius);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            text-decoration: none;
            color: inherit;
            background: transparent;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
        }

        .btn-ghost {
            color: white;
            padding: 0.5rem;
        }

        .btn-ghost:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .auth-screen {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2rem 1rem;
            flex: 1;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }

        .auth-card {
            background: white;
            color: var(--text);
            padding: 2rem;
            border-radius: var(--radius);
            box-shadow: var(--shadow-lg);
            width: 100%;
            max-width: 400px;
        }

        .auth-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            text-align: center;
            color: var(--primary);
        }

        .form-group {
            margin-bottom: 1rem;
        }

        .form-label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            color: var(--text);
        }

        .form-input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            font-size: 1rem;
            transition: var(--transition);
        }

        .form-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            background: var(--light);
        }

        .chat-messages::-webkit-scrollbar {
            width: 6px;
        }

        .chat-messages::-webkit-scrollbar-track {
            background: var(--light);
        }

        .chat-messages::-webkit-scrollbar-thumb {
            background: var(--gray);
            border-radius: 3px;
        }

        .message {
            display: flex;
            gap: 0.75rem;
            animation: slideIn 0.2s ease-out;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .message.user {
            flex-direction: row-reverse;
        }

        .message-avatar {
            width: 2rem;
            height: 2rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.875rem;
            flex-shrink: 0;
        }

        .message.user .message-avatar {
            background: var(--primary);
            color: white;
        }

        .message.ai .message-avatar {
            background: var(--success);
            color: white;
        }

        .message-content-wrapper {
            flex: 1;
            max-width: 85%;
        }

        .message-bubble {
            padding: 0.75rem 1rem;
            border-radius: var(--radius);
            word-wrap: break-word;
            box-shadow: var(--shadow);
        }

        .message.user .message-bubble {
            background: var(--primary);
            color: white;
        }

        .message.ai .message-bubble {
            background: white;
            color: var(--text);
        }

        .message-actions {
            display: flex;
            gap: 0.5rem;
            margin-top: 0.5rem;
            opacity: 0;
            transition: var(--transition);
        }

        .message:hover .message-actions {
            opacity: 1;
        }

        .action-btn {
            background: none;
            border: none;
            padding: 0.25rem;
            cursor: pointer;
            color: var(--text-light);
            font-size: 0.875rem;
            transition: var(--transition);
        }

        .action-btn:hover {
            color: var(--primary);
        }

        .action-btn.active {
            color: var(--success);
        }

        .message-info {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.25rem;
            font-size: 0.75rem;
            color: var(--text-light);
        }

        .confidence-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
        }

        .confidence-bar {
            width: 2rem;
            height: 0.25rem;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
        }

        .confidence-fill {
            height: 100%;
            transition: width 0.3s ease;
        }

        .typing-indicator {
            display: none;
            padding: 1rem;
            background: var(--light);
        }

        .typing-indicator.active {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-light);
            font-size: 0.875rem;
        }

        .typing-dots {
            display: flex;
            gap: 0.25rem;
        }

        .typing-dot {
            width: 0.5rem;
            height: 0.5rem;
            background: var(--gray);
            border-radius: 50%;
            animation: typing 1.4s infinite;
        }

        .typing-dot:nth-child(2) {
            animation-delay: 0.2s;
        }

        .typing-dot:nth-child(3) {
            animation-delay: 0.4s;
        }

        @keyframes typing {
            0%, 60%, 100% {
                transform: translateY(0);
            }
            30% {
                transform: translateY(-0.5rem);
            }
        }

        .chat-input-container {
            background: white;
            padding: 1rem;
            border-top: 1px solid var(--border);
            display: flex;
            gap: 0.75rem;
            align-items: flex-end;
        }

        .chat-input-wrapper {
            flex: 1;
            position: relative;
        }

        .chat-input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            font-size: 1rem;
            resize: none;
            max-height: 6rem;
            transition: var(--transition);
        }

        .chat-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .send-btn {
            background: var(--primary);
            color: white;
            border: none;
            border-radius: var(--radius);
            width: 2.5rem;
            height: 2.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: var(--transition);
            flex-shrink: 0;
        }

        .send-btn:hover {
            background: var(--primary-dark);
            transform: scale(1.05);
        }

        .send-btn:disabled {
            background: var(--gray);
            cursor: not-allowed;
            transform: none;
        }

        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 1rem;
        }

        .modal.active {
            display: flex;
        }

        .modal-content {
            background: white;
            border-radius: var(--radius);
            box-shadow: var(--shadow-lg);
            max-width: 500px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
        }

        .modal-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-title {
            font-size: 1.125rem;
            font-weight: 600;
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text-light);
        }

        .modal-body {
            padding: 1rem;
        }

        .modal-footer {
            padding: 1rem;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
        }

        .report-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .radio-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .radio-option {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .dropdown {
            position: relative;
        }

        .dropdown-menu {
            position: absolute;
            top: 100%;
            right: 0;
            background: white;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: var(--shadow-lg);
            min-width: 12rem;
            display: none;
            z-index: 100;
        }

        .dropdown-menu.active {
            display: block;
        }

        .dropdown-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: var(--transition);
            font-size: 0.875rem;
        }

        .dropdown-item:hover {
            background: var(--light);
        }

        .dropdown-divider {
            height: 1px;
            background: var(--border);
            margin: 0.5rem 0;
        }

        .loading {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .spinner {
            width: 1rem;
            height: 1rem;
            border: 2px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .alert {
            padding: 0.75rem 1rem;
            border-radius: var(--radius);
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }

        .alert-error {
            background: #fef2f2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }

        .alert-success {
            background: #f0fdf4;
            color: #166534;
            border: 1px solid #bbf7d0;
        }

        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 3rem 1rem;
            color: var(--text-light);
            text-align: center;
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        .empty-state h3 {
            font-size: 1.125rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
        }

        .empty-state p {
            font-size: 0.875rem;
            max-width: 20rem;
        }

        .hidden {
            display: none !important;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                data-theme: dark;
                --light: #0f172a;
                --text: #f8fafc;
                --text-light: #94a3b8;
                --border: #334155;
                --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.3), 0 1px 2px -1px rgb(0 0 0 / 0.3);
            }

            body {
                background: var(--dark);
            }

            .app-container {
                background: var(--light);
            }

            .message.ai .message-bubble {
                background: var(--dark);
            }

            .chat-input-container {
                background: var(--dark);
            }

            .chat-input {
                background: var(--light);
                border-color: var(--border);
                color: var(--text);
            }

            .dropdown-menu {
                background: var(--dark);
                border-color: var(--border);
            }

            .modal-content {
                background: var(--light);
            }
        }

        .fade-in {
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }

        .slide-up {
            animation: slideUp 0.3s ease-out;
        }

        @keyframes slideUp {
            from {
                transform: translateY(20px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <header class="header">
            <div class="header-title">
                <i class="fas fa-robot"></i>
                <span>AI Assistant</span>
            </div>
            <div class="header-actions">
                <?php if ($isLoggedIn): ?>
                    <div class="dropdown">
                        <button class="btn btn-ghost" onclick="toggleDropdown()">
                            <i class="fas fa-user"></i>
                        </button>
                        <div class="dropdown-menu" id="userDropdown">
                            <div class="dropdown-item">
                                <i class="fas fa-user-circle"></i>
                                <span><?php echo htmlspecialchars($_SESSION['username'] ?? 'User'); ?></span>
                            </div>
                            <div class="dropdown-divider"></div>
                            <div class="dropdown-item" onclick="logout()">
                                <i class="fas fa-sign-out-alt"></i>
                                <span>Logout</span>
                            </div>
                        </div>
                    </div>
                <?php else: ?>
                    <button class="btn btn-ghost" onclick="showLogin()">
                        <i class="fas fa-sign-in-alt"></i>
                        <span>Login</span>
                    </button>
                <?php endif; ?>
            </div>
        </header>

        <main class="main-content" id="mainContent">
            <?php if (!$isLoggedIn): ?>
                <div class="auth-screen">
                    <div class="auth-card slide-up">
                        <div class="auth-title">
                            <i class="fas fa-robot"></i>
                            AI Assistant
                        </div>
                        
                        <div id="loginForm">
                            <div id="loginError" class="alert alert-error hidden"></div>
                            
                            <div class="form-group">
                                <label class="form-label">Username</label>
                                <input type="text" class="form-input" id="loginUsername" placeholder="Enter username" required>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Password</label>
                                <input type="password" class="form-input" id="loginPassword" placeholder="Enter password" required>
                            </div>
                            
                            <button class="btn btn-primary" onclick="login()" style="width: 100%;">
                                <span id="loginBtnText">Login</span>
                                <div id="loginSpinner" class="spinner hidden"></div>
                            </button>
                            
                            <p style="text-align: center; margin-top: 1rem; font-size: 0.875rem; color: var(--text-light);">
                                Try: admin / Admin@123
                            </p>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="chat-container">
                    <div class="chat-messages" id="chatMessages">
                        <div class="empty-state">
                            <i class="fas fa-comments"></i>
                            <h3>Welcome to AI Assistant</h3>
                            <p>Ask me anything. I'm here to help!</p>
                        </div>
                    </div>
                    
                    <div class="typing-indicator" id="typingIndicator">
                        <div class="typing-dots">
                            <div class="typing-dot"></div>
                            <div class="typing-dot"></div>
                            <div class="typing-dot"></div>
                        </div>
                        <span>Thinking...</span>
                    </div>
                    
                    <div class="chat-input-container">
                        <div class="chat-input-wrapper">
                            <textarea 
                                class="chat-input" 
                                id="chatInput" 
                                placeholder="Type your message..."
                                rows="1"
                                onkeydown="handleChatKeydown(event)"
                                oninput="autoResize(this)"
                            ></textarea>
                        </div>
                        <button class="send-btn" id="sendBtn" onclick="sendMessage()">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </div>
            <?php endif; ?>
        </main>
    </div>

    <div class="modal" id="reportModal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title">Report Response</div>
                <button class="modal-close" onclick="closeReportModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div id="reportError" class="alert alert-error hidden"></div>
                <form class="report-form" id="reportForm">
                    <input type="hidden" id="reportResponseId">
                    <input type="hidden" id="reportQuestionText">
                    <input type="hidden" id="reportResponseText">
                    
                    <div class="form-group">
                        <label class="form-label">Report Type</label>
                        <div class="radio-group">
                            <label class="radio-option">
                                <input type="radio" name="reportType" value="incorrect" checked>
                                <span>Incorrect Information</span>
                            </label>
                            <label class="radio-option">
                                <input type="radio" name="reportType" value="inappropriate">
                                <span>Inappropriate Content</span>
                            </label>
                            <label class="radio-option">
                                <input type="radio" name="reportType" value="spam">
                                <span>Spam</span>
                            </label>
                            <label class="radio-option">
                                <input type="radio" name="reportType" value="other">
                                <span>Other</span>
                            </label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label" for="reportDescription">Description (Optional)</label>
                        <textarea class="form-input" id="reportDescription" rows="3" 
                                 placeholder="Please provide details about the issue..."></textarea>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeReportModal()">Cancel</button>
                <button class="btn btn-primary" onclick="submitReport()">
                    <span id="reportBtnText">Submit Report</span>
                    <div id="reportSpinner" class="spinner hidden"></div>
                </button>
            </div>
        </div>
    </div>

    <script>
        const API_URL = 'app.php';
        let currentSessionId = '<?php echo getCurrentSessionId(); ?>';
        let currentUserId = '<?php echo $_SESSION['user_id'] ?? null; ?>';
        let chatHistory = [];
        let isProcessing = false;

        function showLogin() {
            location.reload();
        }

        async function login() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            const errorEl = document.getElementById('loginError');
            const btnText = document.getElementById('loginBtnText');
            const spinner = document.getElementById('loginSpinner');

            if (!username || !password) {
                errorEl.textContent = 'Please enter username and password';
                errorEl.classList.remove('hidden');
                return;
            }

            errorEl.classList.add('hidden');
            btnText.classList.add('hidden');
            spinner.classList.remove('hidden');

            try {
                const formData = new FormData();
                formData.append('action', 'login');
                formData.append('username', username);
                formData.append('password', password);
                formData.append('csrf_token', '<?php echo $csrfToken; ?>');

                const response = await fetch(API_URL, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    location.reload();
                } else {
                    errorEl.textContent = result.message;
                    errorEl.classList.remove('hidden');
                }
            } catch (error) {
                errorEl.textContent = 'Login failed. Please try again.';
                errorEl.classList.remove('hidden');
            } finally {
                btnText.classList.remove('hidden');
                spinner.classList.add('hidden');
            }
        }

        async function logout() {
            try {
                const formData = new FormData();
                formData.append('action', 'logout');
                formData.append('csrf_token', '<?php echo $csrfToken; ?>');

                await fetch(API_URL, {
                    method: 'POST',
                    body: formData
                });
            } catch (error) {
                console.error('Logout error:', error);
            } finally {
                location.reload();
            }
        }

        function handleChatKeydown(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
            }
        }

        function autoResize(textarea) {
            textarea.style.height = 'auto';
            textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
        }

        async function sendMessage() {
            const input = document.getElementById('chatInput');
            const message = input.value.trim();
            
            if (!message || isProcessing) return;

            isProcessing = true;
            input.value = '';
            input.style.height = 'auto';
            
            addMessageToChat(message, 'user');
            showTypingIndicator();
            disableInput();

            try {
                const formData = new FormData();
                formData.append('action', 'chat');
                formData.append('question', message);
                formData.append('csrf_token', '<?php echo $csrfToken; ?>');

                const response = await fetch(API_URL, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    addMessageToChat(result.response, 'ai', result);
                } else {
                    addErrorToChat('Failed to get response. Please try again.');
                }
            } catch (error) {
                console.error('Chat error:', error);
                addErrorToChat('Error communicating with server.');
            } finally {
                hideTypingIndicator();
                enableInput();
                isProcessing = false;
            }
        }

        function addMessageToChat(content, sender, data = null) {
            const messagesContainer = document.getElementById('chatMessages');
            
            if (messagesContainer.querySelector('.empty-state')) {
                messagesContainer.innerHTML = '';
            }

            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${sender} fade-in`;
            
            const avatar = sender === 'user' ? 
                '<i class="fas fa-user"></i>' : 
                '<i class="fas fa-robot"></i>';
            
            let messageContent = `<div class="message-content-wrapper">
                <div class="message-bubble">${escapeHtml(content)}</div>`;

            if (sender === 'ai' && data) {
                const responseId = data.response_id;
                const confidencePercent = Math.round((data.confidence || 0) * 100);
                const confidenceColor = confidencePercent >= 80 ? '#10b981' : 
                                       confidencePercent >= 60 ? '#f59e0b' : '#ef4444';
                
                messageContent += `
                    <div class="message-actions">
                        <button class="action-btn" onclick="rateResponse(${responseId}, 1, this)" title="Helpful">
                            <i class="fas fa-thumbs-up"></i>
                        </button>
                        <button class="action-btn" onclick="rateResponse(${responseId}, 0, this)" title="Not Helpful">
                            <i class="fas fa-thumbs-down"></i>
                        </button>
                        <button class="action-btn" onclick="showReportModal(${responseId}, '${escapeHtml(data.question)}', '${escapeHtml(content)}')" title="Report">
                            <i class="fas fa-flag"></i>
                        </button>
                    </div>
                    <div class="message-info">
                        <div class="confidence-indicator">
                            <span>Confidence:</span>
                            <div class="confidence-bar">
                                <div class="confidence-fill" style="width: ${confidencePercent}%; background: ${confidenceColor}"></div>
                            </div>
                            <span>${confidencePercent}%</span>
                        </div>
                        ${data.cached ? '<span><i class="fas fa-database" title="Cached"></i></span>' : ''}
                    </div>`;
            }

            messageContent += '</div>';
            
            messageDiv.innerHTML = `
                <div class="message-avatar">${avatar}</div>
                ${messageContent}
            `;
            
            messagesContainer.appendChild(messageDiv);
            scrollToBottom();
            
            chatHistory.push({
                id: Date.now(),
                content: content,
                sender: sender,
                timestamp: new Date(),
                data: data
            });
        }

        function addErrorToChat(error) {
            addMessageToChat(`<i class="fas fa-exclamation-triangle"></i> ${error}`, 'ai');
        }

        function rateResponse(responseId, rating, button) {
            const formData = new FormData();
            formData.append('action', 'rate_response');
            formData.append('response_id', responseId);
            formData.append('rating', rating);
            formData.append('csrf_token', '<?php echo $csrfToken; ?>');

            fetch(API_URL, {
                method: 'POST',
                body: formData
            });

            const parent = button.parentElement;
            parent.querySelectorAll('.action-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.onclick = null;
            });
            
            button.classList.add('active');
        }

        function showReportModal(responseId, question, response) {
            document.getElementById('reportResponseId').value = responseId;
            document.getElementById('reportQuestionText').value = question;
            document.getElementById('reportResponseText').value = response;
            document.getElementById('reportModal').classList.add('active');
        }

        function closeReportModal() {
            document.getElementById('reportModal').classList.remove('active');
            document.getElementById('reportForm').reset();
            document.getElementById('reportError').classList.add('hidden');
        }

        async function submitReport() {
            const responseId = document.getElementById('reportResponseId').value;
            const reportType = document.querySelector('input[name="reportType"]:checked').value;
            const description = document.getElementById('reportDescription').value;
            const questionText = document.getElementById('reportQuestionText').value;
            const responseText = document.getElementById('reportResponseText').value;
            
            const errorEl = document.getElementById('reportError');
            const btnText = document.getElementById('reportBtnText');
            const spinner = document.getElementById('reportSpinner');

            errorEl.classList.add('hidden');
            btnText.classList.add('hidden');
            spinner.classList.remove('hidden');

            try {
                const formData = new FormData();
                formData.append('action', 'report_response');
                formData.append('response_id', responseId);
                formData.append('report_type', reportType);
                formData.append('description', description);
                formData.append('question_text', questionText);
                formData.append('response_text', responseText);
                formData.append('csrf_token', '<?php echo $csrfToken; ?>');

                const response = await fetch(API_URL, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    closeReportModal();
                    showToast('Report submitted successfully', 'success');
                } else {
                    errorEl.textContent = result.message;
                    errorEl.classList.remove('hidden');
                }
            } catch (error) {
                errorEl.textContent = 'Failed to submit report. Please try again.';
                errorEl.classList.remove('hidden');
            } finally {
                btnText.classList.remove('hidden');
                spinner.classList.add('hidden');
            }
        }

        function showTypingIndicator() {
            document.getElementById('typingIndicator').classList.add('active');
        }

        function hideTypingIndicator() {
            document.getElementById('typingIndicator').classList.remove('active');
        }

        function disableInput() {
            document.getElementById('chatInput').disabled = true;
            document.getElementById('sendBtn').disabled = true;
        }

        function enableInput() {
            document.getElementById('chatInput').disabled = false;
            document.getElementById('sendBtn').disabled = false;
            document.getElementById('chatInput').focus();
        }

        function scrollToBottom() {
            const messagesContainer = document.getElementById('chatMessages');
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function toggleDropdown() {
            const dropdown = document.getElementById('userDropdown');
            dropdown.classList.toggle('active');
        }

        function showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.className = `alert alert-${type}`;
            toast.style.position = 'fixed';
            toast.style.bottom = '1rem';
            toast.style.right = '1rem';
            toast.style.zIndex = '1000';
            toast.textContent = message;
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.remove();
            }, 3000);
        }

        document.addEventListener('click', (e) => {
            const dropdown = document.getElementById('userDropdown');
            const userBtn = e.target.closest('.btn-ghost');
            
            if (!userBtn || !userBtn.onclick || !userBtn.onclick.toString().includes('toggleDropdown')) {
                if (dropdown) {
                    dropdown.classList.remove('active');
                }
            }
        });

        document.addEventListener('DOMContentLoaded', () => {
            const chatInput = document.getElementById('chatInput');
            if (chatInput) {
                chatInput.focus();
            }
        });
    </script>
</body>
</html>