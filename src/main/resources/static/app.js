(function () {
    'use strict';

    var API_BASE = resolveApiBase();
    var baselineToken = '';
    var sessionCredentials = { username: '', password: '' };

    var VIEWS = ['view-login', 'view-register', 'view-dashboard'];

    var loginForm = document.getElementById('loginForm');
    var loginUsername = document.getElementById('loginUsername');
    var loginPassword = document.getElementById('loginPassword');
    var loginStatus = document.getElementById('loginStatus');
    var goRegisterLink = document.getElementById('goRegisterLink');

    var registerForm = document.getElementById('registerForm');
    var registerUsername = document.getElementById('registerUsername');
    var registerEmail = document.getElementById('registerEmail');
    var registerPassword = document.getElementById('registerPassword');
    var registerStatus = document.getElementById('registerStatus');
    var goLoginLink = document.getElementById('goLoginLink');

    var dashboardUser = document.getElementById('dashboardUser');
    var signOutBtn = document.getElementById('signOutBtn');
    var generateBtn = document.getElementById('generateBtn');
    var generatedToken = document.getElementById('generatedToken');
    var tokenInput = document.getElementById('tokenInput');
    var injectNoneBtn = document.getElementById('injectNoneBtn');
    var verifyBtn = document.getElementById('verifyBtn');
    var terminal = document.getElementById('terminal');

    var TERMINAL_BASE =
        'px-4 py-4 text-sm font-mono leading-relaxed min-h-[88px] whitespace-pre-wrap bg-black transition-colors duration-200';

    function resolveApiBase() {
        var protocol = window.location.protocol;
        var hostname = window.location.hostname;
        var port = window.location.port;
        if (port === '8080' || (hostname === 'localhost' && !port)) {
            return protocol + '//' + hostname + ':8080/api/v1';
        }
        return 'http://localhost:8080/api/v1';
    }

    function showView(viewId) {
        VIEWS.forEach(function (id) {
            document.getElementById(id).classList.add('hidden');
        });
        document.getElementById(viewId).classList.remove('hidden');
    }

    function showStatus(element, message) {
        element.textContent = message;
        element.classList.remove('hidden');
    }

    function hideStatus(element) {
        element.classList.add('hidden');
        element.textContent = '';
    }

    function setTerminal(message, tone) {
        terminal.textContent = message;
        if (tone === 'ok') {
            terminal.className = TERMINAL_BASE + ' text-[#e5e5e5]';
        } else if (tone === 'blocked') {
            terminal.className = TERMINAL_BASE + ' text-[#dc2626]';
        } else {
            terminal.className = TERMINAL_BASE + ' text-[#737373]';
        }
    }

    function updateLabControls(hasToken) {
        verifyBtn.disabled = !hasToken;
        injectNoneBtn.disabled = !hasToken;
    }

    function clearTokenSurfaces() {
        baselineToken = '';
        generatedToken.textContent = '';
        tokenInput.value = '';
        updateLabControls(false);
        setTerminal('Awaiting token verification.', 'idle');
    }

    function applyGeneratedToken(token) {
        baselineToken = token;
        generatedToken.textContent = token;
        updateLabControls(!!tokenInput.value.trim());
        setTerminal('Token issued in Secure Output. Manually paste into the lab to verify or inject.', 'idle');
    }

    function resetDashboard() {
        sessionCredentials = { username: '', password: '' };
        clearTokenSurfaces();
    }

    function enterDashboard(username) {
        dashboardUser.textContent = 'Signed in as ' + username;
        clearTokenSurfaces();
        showView('view-dashboard');
    }

    function extractErrorMessage(body, fallback) {
        if (!body) {
            return fallback;
        }
        if (typeof body === 'string') {
            return body;
        }
        if (body.error && typeof body.error === 'string') {
            return body.error;
        }
        if (body.message) {
            return body.message;
        }
        return fallback;
    }

    async function apiRequest(path, options) {
        var headers = { 'Content-Type': 'application/json' };
        if (options.headers) {
            Object.keys(options.headers).forEach(function (key) {
                headers[key] = options.headers[key];
            });
        }

        var response = await fetch(API_BASE + path, {
            method: options.method || 'GET',
            headers: headers,
            body: options.body,
            credentials: 'include'
        });

        var text = await response.text();
        var body = null;
        if (text) {
            try {
                body = JSON.parse(text);
            } catch (e) {
                body = text;
            }
        }
        return { response: response, body: body };
    }

    async function fetchAccessToken(username, password) {
        var result = await apiRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username: username, password: password })
        });

        if (result.response.ok && result.body && result.body.accessToken) {
            return result.body.accessToken;
        }

        throw new Error(extractErrorMessage(result.body, 'Authentication failed.'));
    }

    function base64UrlEncode(str) {
        var bytes = new TextEncoder().encode(str);
        var binary = '';
        bytes.forEach(function (b) {
            binary += String.fromCharCode(b);
        });
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decodeJwtSegment(token, index) {
        var part = token.split('.')[index];
        var padded = part.replace(/-/g, '+').replace(/_/g, '/');
        return atob(padded);
    }

    function buildAlgNoneToken(originalToken) {
        var parts = originalToken.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT structure. Paste a valid token into the lab first.');
        }

        var header = JSON.parse(decodeJwtSegment(originalToken, 0));
        header.alg = 'none';

        var newHeader = base64UrlEncode(JSON.stringify(header));
        return newHeader + '.' + parts[1] + '.';
    }

    goRegisterLink.addEventListener('click', function () {
        hideStatus(loginStatus);
        showView('view-register');
    });

    goLoginLink.addEventListener('click', function () {
        hideStatus(registerStatus);
        showView('view-login');
    });

    registerForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        var username = registerUsername.value.trim();
        var email = registerEmail.value.trim();
        var password = registerPassword.value;

        if (!username || !email || !password) {
            showStatus(registerStatus, 'All fields are required.');
            return;
        }

        try {
            var result = await apiRequest('/auth/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password,
                    role: 'ROLE_USER'
                })
            });

            if (result.response.ok) {
                registerForm.reset();
                hideStatus(registerStatus);
                showView('view-login');
                showStatus(loginStatus, 'Account created. Sign in to continue.');
            } else {
                showStatus(registerStatus, extractErrorMessage(result.body, 'Registration failed.'));
            }
        } catch (error) {
            showStatus(registerStatus, 'Network error: ' + error.message);
        }
    });

    loginForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        var username = loginUsername.value.trim();
        var password = loginPassword.value;

        if (!username || !password) {
            showStatus(loginStatus, 'Username and password required.');
            return;
        }

        try {
            await fetchAccessToken(username, password);
            sessionCredentials = { username: username, password: password };
            loginForm.reset();
            hideStatus(loginStatus);
            enterDashboard(username);
        } catch (error) {
            showStatus(loginStatus, error.message);
        }
    });

    signOutBtn.addEventListener('click', function () {
        resetDashboard();
        showView('view-login');
    });

    generateBtn.addEventListener('click', async function () {
        if (!sessionCredentials.username || !sessionCredentials.password) {
            setTerminal('Session expired. Sign in again.', 'idle');
            showView('view-login');
            return;
        }

        try {
            var token = await fetchAccessToken(
                sessionCredentials.username,
                sessionCredentials.password
            );
            applyGeneratedToken(token);
        } catch (error) {
            setTerminal(error.message, 'blocked');
        }
    });

    injectNoneBtn.addEventListener('click', function () {
        var token = tokenInput.value.trim();
        if (!token) {
            setTerminal('No token available to inject.', 'idle');
            return;
        }

        try {
            var attackToken = buildAlgNoneToken(token);
            tokenInput.value = attackToken;
            updateLabControls(true);
            setTerminal('alg=none payload injected into textarea. Route token to test proactive filter.', 'idle');
        } catch (error) {
            setTerminal(error.message, 'blocked');
        }
    });

    verifyBtn.addEventListener('click', async function () {
        var token = tokenInput.value.trim();
        if (!token) {
            setTerminal('No token to route.', 'idle');
            return;
        }

        var isModified = baselineToken === '' || token !== baselineToken;

        try {
            var result = await apiRequest('/secure/data', {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token }
            });

            if (!isModified && result.response.status === 200) {
                setTerminal('Status 200 OK: Valid RSA Signature. Access Granted.', 'ok');
                return;
            }

            if (isModified || result.response.status === 401) {
                setTerminal('Status 401 Unauthorized: Proactive Filter Blocked Payload.', 'blocked');
                return;
            }

            setTerminal(
                'Status ' + result.response.status + ': ' + extractErrorMessage(result.body, 'Request rejected.'),
                'blocked'
            );
        } catch (error) {
            setTerminal('Status 401 Unauthorized: Proactive Filter Blocked Payload.', 'blocked');
        }
    });

    tokenInput.addEventListener('input', function () {
        updateLabControls(!!tokenInput.value.trim());
    });

    showView('view-login');
})();
