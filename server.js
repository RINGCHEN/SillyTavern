#!/usr/bin/env node

// native node modules
import path from 'node:path';
import util from 'node:util';
import net from 'node:net';
import dns from 'node:dns';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

import cors from 'cors';
import { csrfSync } from 'csrf-sync';
import express from 'express';
import compression from 'compression';
import cookieSession from 'cookie-session';
import multer from 'multer';
import responseTime from 'response-time';
import helmet from 'helmet';
import bodyParser from 'body-parser';
import open from 'open';
import fetch from 'node-fetch'; // Added for making requests to LoI

// local library imports
import { serverEvents, EVENT_NAMES } from './src/server-events.js';
import { CommandLineParser } from './src/command-line.js';
import { loadPlugins } from './src/plugin-loader.js';
import {
    initUserStorage,
    getCookieSecret,
    getCookieSessionName,
    ensurePublicDirectoriesExist,
    getUserDirectoriesList,
    migrateSystemPrompts,
    migrateUserData,
    requireLoginMiddleware,
    setUserDataMiddleware,
    shouldRedirectToLogin,
    cleanUploads,
    getSessionCookieAge,
    verifySecuritySettings,
    loginPageMiddleware,
} from './src/users.js';

import getWebpackServeMiddleware from './src/middleware/webpack-serve.js';
import basicAuthMiddleware from './src/middleware/basicAuth.js';
import getWhitelistMiddleware from './src/middleware/whitelist.js';
import accessLoggerMiddleware, { getAccessLogPath, migrateAccessLog } from './src/middleware/accessLogWriter.js';
import multerMonkeyPatch from './src/middleware/multerMonkeyPatch.js';
import initRequestProxy from './src/request-proxy.js';
import getCacheBusterMiddleware from './src/middleware/cacheBuster.js';
import corsProxyMiddleware from './src/middleware/corsProxy.js';
import {
    getVersion,
    color,
    removeColorFormatting,
    getSeparator,
    safeReadFileSync,
    setupLogLevel,
    setWindowTitle,
} from './src/util.js';
import { UPLOADS_DIRECTORY } from './src/constants.js';
import { ensureThumbnailCache } from './src/endpoints/thumbnails.js';

// Routers
import { router as usersPublicRouter } from './src/endpoints/users-public.js';
import { init as statsInit, onExit as statsOnExit } from './src/endpoints/stats.js';
import { checkForNewContent } from './src/endpoints/content-manager.js';
import { init as settingsInit } from './src/endpoints/settings.js';
import { redirectDeprecatedEndpoints, ServerStartup, setupPrivateEndpoints } from './src/server-startup.js';

// Unrestrict console logs display limit
util.inspect.defaultOptions.maxArrayLength = null;
util.inspect.defaultOptions.maxStringLength = null;
util.inspect.defaultOptions.depth = 4;

// Set a working directory for the server
const serverDirectory = import.meta.dirname ?? path.dirname(fileURLToPath(import.meta.url));
console.log(`Node version: ${process.version}. Running in ${process.env.NODE_ENV} environment. Server directory: ${serverDirectory}`);
process.chdir(serverDirectory);

// Work around a node v20.0.0, v20.1.0, and v20.2.0 bug. The issue was fixed in v20.3.0.
// https://github.com/nodejs/node/issues/47822#issuecomment-1564708870
// Safe to remove once support for Node v20 is dropped.
if (process.versions && process.versions.node && process.versions.node.match(/20\.[0-2]\.0/)) {
    // @ts-ignore
    if (net.setDefaultAutoSelectFamily) net.setDefaultAutoSelectFamily(false);
}

const cliArgs = new CommandLineParser().parse(process.argv);
globalThis.DATA_ROOT = cliArgs.dataRoot;
globalThis.COMMAND_LINE_ARGS = cliArgs;

if (!cliArgs.enableIPv6 && !cliArgs.enableIPv4) {
    console.error('error: You can\'t disable all internet protocols: at least IPv6 or IPv4 must be enabled.');
    process.exit(1);
}

try {
    if (cliArgs.dnsPreferIPv6) {
        dns.setDefaultResultOrder('ipv6first');
        console.log('Preferring IPv6 for DNS resolution');
    } else {
        dns.setDefaultResultOrder('ipv4first');
        console.log('Preferring IPv4 for DNS resolution');
    }
} catch (error) {
    console.warn('Failed to set DNS resolution order. Possibly unsupported in this Node version.');
}

const app = express();
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(compression());
app.use(responseTime());

app.use(bodyParser.json({ limit: '200mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '200mb' }));

// CORS Settings //
const CORS = cors({
    origin: 'null',
    methods: ['OPTIONS'],
});

app.use(CORS);

if (cliArgs.listen && cliArgs.basicAuthMode) {
    app.use(basicAuthMiddleware);
}

if (cliArgs.whitelistMode) {
    const whitelistMiddleware = await getWhitelistMiddleware();
    app.use(whitelistMiddleware);
}

if (cliArgs.listen) {
    app.use(accessLoggerMiddleware());
}

if (cliArgs.enableCorsProxy) {
    app.use('/proxy/:url(*)', corsProxyMiddleware);
} else {
    app.use('/proxy/:url(*)', async (_, res) => {
        const message = 'CORS proxy is disabled. Enable it in config.yaml or use the --corsProxy flag.';
        console.log(message);
        res.status(404).send(message);
    });
}

app.use(cookieSession({
    name: getCookieSessionName(),
    sameSite: 'strict',
    httpOnly: true,
    maxAge: getSessionCookieAge(),
    secret: getCookieSecret(globalThis.DATA_ROOT),
}));

app.use(setUserDataMiddleware);

// CSRF Protection //
if (!cliArgs.disableCsrf) {
    const csrfSyncProtection = csrfSync({
        getTokenFromState: (req) => {
            if (!req.session) {
                console.error('(CSRF error) getTokenFromState: Session object not initialized');
                return;
            }
            return req.session.csrfToken;
        },
        getTokenFromRequest: (req) => {
            return req.headers['x-csrf-token']?.toString();
        },
        storeTokenInState: (req, token) => {
            if (!req.session) {
                console.error('(CSRF error) storeTokenInState: Session object not initialized');
                return;
            }
            req.session.csrfToken = token;
        },
        size: 32,
    });

    app.get('/csrf-token', (req, res) => {
        res.json({
            'token': csrfSyncProtection.generateToken(req),
        });
    });

    // Customize the error message
    csrfSyncProtection.invalidCsrfTokenError.message = color.red('Invalid CSRF token. Please refresh the page and try again.');
    csrfSyncProtection.invalidCsrfTokenError.stack = undefined;

    // Route to initiate login flow with LoI backend
    app.get('/auth/initiate-loi-login', (req, res) => {
        if (!req.session) {
            console.error('Session not available for initiating LoI login.');
            return res.status(500).json({ error: 'Session unavailable.' });
        }

        // Generate a random state parameter for CSRF protection
        const state = crypto.randomBytes(16).toString('hex');

        // Store the state in the session
        // We'll use this later in the callback to verify the request origin
        req.session.loiAuthState = state;

        // TODO: Get LoI base URL from config/environment variable
        const loiBaseUrl = process.env.LOI_BASE_URL || 'https://your-loi-backend.onrender.com'; // Replace with actual LoI URL
        const loiInitiateUrl = `${loiBaseUrl}/auth/st-initiate/?state=${state}`;

        console.log(`Initiating LoI login. State: ${state}. Redirect URL: ${loiInitiateUrl}`); // Log for debugging

        // Send the URL back to the frontend
        res.json({ loiAuthUrl: loiInitiateUrl });
    });

    app.use(csrfSyncProtection.csrfSynchronisedProtection);
} else { // CSRF is disabled
    console.warn('\nCSRF protection is disabled. This will make your server vulnerable to CSRF attacks.\n');
    app.get('/csrf-token', (req, res) => {
        res.json({
            'token': 'disabled',
        });
    });

    // Route to initiate login flow with LoI backend (CSRF disabled version)
    // Note: Even with CSRF disabled for ST itself, the state parameter is still crucial
    // for the OAuth-like flow to prevent CSRF during the redirect dance.
    app.get('/auth/initiate-loi-login', (req, res) => {
        if (!req.session) {
            console.error('Session not available for initiating LoI login.');
            return res.status(500).json({ error: 'Session unavailable.' });
        }

        const state = crypto.randomBytes(16).toString('hex');
        req.session.loiAuthState = state;

        // TODO: Get LoI base URL from config/environment variable
        const loiBaseUrl = process.env.LOI_BASE_URL || 'https://your-loi-backend.onrender.com'; // Replace with actual LoI URL
        const loiInitiateUrl = `${loiBaseUrl}/auth/st-initiate/?state=${state}`;

        console.log(`Initiating LoI login (CSRF disabled). State: ${state}. Redirect URL: ${loiInitiateUrl}`); // Log for debugging

        res.json({ loiAuthUrl: loiInitiateUrl });
    });

    // LoI Authentication Callback Route
    app.get('/auth/callback', (req, res) => {
        const { access_token, refresh_token, state } = req.query;
        const expectedState = req.session?.loiAuthState;

        // Clear the state from session regardless of success or failure
        if (req.session) {
            delete req.session.loiAuthState;
        }

        // Verify state parameter for CSRF protection
        if (!state || !expectedState || state !== expectedState) {
            console.error('LoI Auth Callback Error: Invalid state parameter.');
            // Redirect to login or an error page
            return res.redirect('/login?error=invalid_state');
        }

        // Check if tokens were received
        if (!access_token || !refresh_token) {
            console.error('LoI Auth Callback Error: Missing tokens.');
            // Redirect to login or an error page
            return res.redirect('/login?error=missing_tokens');
        }

        // Store tokens securely in the session
        if (req.session) {
            req.session.loiAccessToken = access_token;
            req.session.loiRefreshToken = refresh_token;
            // Mark the session as authenticated via LoI (optional, but can be useful)
            req.session.isAuthenticatedWithLoI = true;
            // Touch the session to update its expiry? cookie-session might do this automatically
            // req.session.nowInMinutes = Math.floor(Date.now() / 60e3);

            console.log('LoI Authentication successful. Tokens stored in session.');

            // Redirect user to the main application page
            return res.redirect('/');
        } else {
            console.error('LoI Auth Callback Error: Session not available to store tokens.');
            // This case should ideally not happen if session middleware is working
            return res.redirect('/login?error=session_error');
        }
    });

    // LoI Logout Route
    app.post('/auth/logout', (req, res) => { // Use POST for actions that change state
        if (req.session) {
            // Clear LoI specific session data
            delete req.session.loiAccessToken;
            delete req.session.loiRefreshToken;
            delete req.session.isAuthenticatedWithLoI;
            // Optionally destroy the whole session if appropriate,
            // or just clear the LoI parts if ST has its own separate login state.
            // For simplicity here, we just clear LoI parts.
            // req.session = null; // Destroys the session

            console.log('LoI tokens cleared from session during logout.');

            // TODO: Optionally call LoI backend to invalidate refresh token

            res.status(200).json({ message: 'Logged out successfully' });
            // Or redirect: res.redirect('/login');
            // Sending JSON might be better if called via fetch from frontend JS
        } else {
            // Session doesn't exist, maybe already logged out or error
            res.status(200).json({ message: 'No active session found' });
        }
    });
}

// Static files
// Host index page
app.get('/', getCacheBusterMiddleware(), (request, response) => {
    if (shouldRedirectToLogin(request)) {
        const query = request.url.split('?')[1];
        const redirectUrl = query ? `/login?${query}` : '/login';
        return response.redirect(redirectUrl);
    }

    return response.sendFile('index.html', { root: path.join(process.cwd(), 'public') });
});

// Host login page
app.get('/login', loginPageMiddleware);

// Host frontend assets
const webpackMiddleware = getWebpackServeMiddleware();
app.use(webpackMiddleware);
app.use(express.static(process.cwd() + '/public', {}));

// Public API
app.use('/api/users', usersPublicRouter);

// Everything below this line requires authentication
app.use(requireLoginMiddleware);
app.get('/api/ping', (request, response) => {
    if (request.query.extend && request.session) {
        request.session.touch = Date.now();
    }

    response.sendStatus(204);
});

// --- LoI API Proxy Routes ---

// Helper function to refresh LoI tokens
async function refreshLoIToken(req) {
    if (!req.session?.loiRefreshToken) {
        console.error('LoI Refresh Error: No refresh token found in session.');
        return false; // Indicate refresh failure
    }

    const refreshToken = req.session.loiRefreshToken;
    // TODO: Get LoI base URL from config/environment variable
    const loiBaseUrl = process.env.LOI_BASE_URL || 'https://your-loi-backend.onrender.com'; // Replace with actual LoI URL
    const loiRefreshUrl = `${loiBaseUrl}/api/auth/tokens/refresh/`; // Assuming this is the LoI refresh endpoint

    console.log(`Attempting to refresh LoI token using endpoint: ${loiRefreshUrl}`);

    try {
        const refreshResponse = await fetch(loiRefreshUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify({ refresh: refreshToken }), // Assuming LoI expects { "refresh": "..." }
        });

        if (!refreshResponse.ok) {
            const errorBody = await refreshResponse.text();
            console.error(`LoI Refresh Error: Refresh request failed with status ${refreshResponse.status}. Body: ${errorBody}`);
            // Clear potentially invalid tokens from session if refresh fails (important!)
            if (req.session) {
                delete req.session.loiAccessToken;
                delete req.session.loiRefreshToken;
                delete req.session.isAuthenticatedWithLoI;
                console.log('Cleared LoI tokens from session due to refresh failure.');
            }
            return false; // Indicate refresh failure
        }

        // Assuming LoI refresh endpoint returns { "access": "...", "refresh": "..." (optional) }
        const newTokensUnknown = await refreshResponse.json();

        // Type check for the expected token structure
        const isValidTokenResponse = (data) => {
            return typeof data === 'object' && data !== null && typeof data.access === 'string';
        };

        if (!isValidTokenResponse(newTokensUnknown)) {
             console.error('LoI Refresh Error: Refresh response did not contain a valid access token structure.');
             // Clear potentially invalid tokens
             if (req.session) {
                delete req.session.loiAccessToken;
                delete req.session.loiRefreshToken;
                delete req.session.isAuthenticatedWithLoI;
            }
             return false;
        }

        // Now we know newTokensUnknown has at least an 'access' property of type string
        // Now we know newTokensUnknown has at least an 'access' property of type string
        // Update session with new tokens *within the validated scope*
        if (req.session) {
            // Directly use the validated object's properties
            // @ts-ignore - Suppress error as type is validated by isValidTokenResponse
            req.session.loiAccessToken = newTokensUnknown.access;
            // Update refresh token ONLY if LoI sends a new one (implementing rotation)
            // Check if refresh property exists and is a string on the validated object
            // @ts-ignore - Suppress error as type is validated by isValidTokenResponse
            if (typeof newTokensUnknown.refresh === 'string') {
                // @ts-ignore - Suppress error as type is validated by isValidTokenResponse
                req.session.loiRefreshToken = newTokensUnknown.refresh;
                console.log('LoI token refreshed successfully (with new refresh token).');
            } else {
                console.log('LoI token refreshed successfully (reusing existing refresh token).');
            }
            return true; // Indicate refresh success
        } else {
            // This case should ideally not happen if session is available at the start
            console.error('LoI Refresh Error: Session not available to store refreshed tokens.');
            return false; // Indicate refresh failure
        }

    } catch (error) {
        console.error('LoI Refresh Error: Network error during token refresh', error);
        return false; // Indicate refresh failure
    }
}


// Proxy Route for LoI Characters with Refresh Logic
app.get('/api/proxy/loi/characters', async (req, res) => {
    // TODO: Get LoI base URL from config/environment variable
    const loiBaseUrl = process.env.LOI_BASE_URL || 'https://your-loi-backend.onrender.com'; // Replace with actual LoI URL
    const loiCharactersUrl = `${loiBaseUrl}/api/v1/characters/`;

    // Function to make the actual API call
    const makeApiCall = async (token) => {
        return await fetch(loiCharactersUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json',
            },
        });
    };

    if (!req.session?.loiAccessToken) {
        console.error('LoI Proxy Error: Missing access token in session for /characters');
        return res.status(401).json({ error: 'Not authenticated with LoI' });
    }

    try {
        let accessToken = req.session.loiAccessToken;
        console.log(`Proxying GET request to LoI: ${loiCharactersUrl}`); // Debug log
        let loiResponse = await makeApiCall(accessToken);

        // Check if token expired (401 Unauthorized)
        if (loiResponse.status === 401) {
            console.log('LoI Access Token potentially expired for /characters. Attempting refresh...');
            const refreshSuccess = await refreshLoIToken(req); // Attempt refresh

            if (refreshSuccess && req.session?.loiAccessToken) {
                console.log('Token refresh successful. Retrying /characters API call...');
                accessToken = req.session.loiAccessToken; // Get the new token
                loiResponse = await makeApiCall(accessToken); // Retry the request
            } else {
                console.error('LoI Proxy Error: Token refresh failed or session unavailable for /characters.');
                // If refresh failed, return 401 to the client to trigger re-login
                return res.status(401).json({ error: 'Authentication required. Refresh failed.' });
            }
        }

        // Forward the status code from LoI (could be success or other error after retry)
        res.status(loiResponse.status);

        // Stream the response body from LoI back to the client if it exists
        if (loiResponse.body) {
            loiResponse.body.pipe(res);
        } else {
            res.end();
        }

        // If you need to inspect/modify the body, you'd do this instead:
        // if (!loiResponse.ok) {
        //     const errorBody = await loiResponse.text();
        //     console.error(`LoI Proxy Error: /characters returned ${loiResponse.status}. Body: ${errorBody}`);
        //     return res.json({ error: `LoI API Error (${loiResponse.status})`, details: errorBody });
        // }
        // const data = await loiResponse.json();
        // res.json(data);

    } catch (error) {
        console.error('LoI Proxy Error: Failed to fetch /characters', error);
        res.status(500).json({ error: 'Failed to contact LoI service' });
    }
});

// Proxy Route for LoI Chat with Refresh Logic
app.post('/api/proxy/loi/chat', async (req, res) => {
    // TODO: Get LoI base URL from config/environment variable
    const loiBaseUrl = process.env.LOI_BASE_URL || 'https://your-loi-backend.onrender.com'; // Replace with actual LoI URL
    const loiChatUrl = `${loiBaseUrl}/api/v1/chat/`;

    // Function to make the actual API call
    const makeApiCall = async (token, body) => {
        return await fetch(loiChatUrl, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify(body),
        });
    };

    if (!req.session?.loiAccessToken) {
        console.error('LoI Proxy Error: Missing access token in session for /chat');
        return res.status(401).json({ error: 'Not authenticated with LoI' });
    }

    try {
        let accessToken = req.session.loiAccessToken;
        const requestBody = req.body; // Capture original request body
        console.log(`Proxying POST request to LoI: ${loiChatUrl}`); // Debug log
        let loiResponse = await makeApiCall(accessToken, requestBody);

        // Check if token expired (401 Unauthorized)
        if (loiResponse.status === 401) {
            console.log('LoI Access Token potentially expired for /chat. Attempting refresh...');
            const refreshSuccess = await refreshLoIToken(req); // Attempt refresh

            if (refreshSuccess && req.session?.loiAccessToken) {
                console.log('Token refresh successful. Retrying /chat API call...');
                accessToken = req.session.loiAccessToken; // Get the new token
                loiResponse = await makeApiCall(accessToken, requestBody); // Retry the request with original body
            } else {
                console.error('LoI Proxy Error: Token refresh failed or session unavailable for /chat.');
                // If refresh failed, return 401 to the client to trigger re-login
                return res.status(401).json({ error: 'Authentication required. Refresh failed.' });
            }
        }

        // Forward the status code from LoI (could be success or other error after retry)
        res.status(loiResponse.status);

        // Stream the response body from LoI back to the client if it exists
        if (loiResponse.body) {
            loiResponse.body.pipe(res);
        } else {
            res.end();
        }

    } catch (error) {
        console.error('LoI Proxy Error: Failed to fetch /chat', error);
        res.status(500).json({ error: 'Failed to contact LoI service' });
    }
});

// --- End LoI API Proxy Routes ---


// File uploads
const uploadsPath = path.join(cliArgs.dataRoot, UPLOADS_DIRECTORY);
app.use(multer({ dest: uploadsPath, limits: { fieldSize: 10 * 1024 * 1024 } }).single('avatar'));
app.use(multerMonkeyPatch);

app.get('/version', async function (_, response) {
    const data = await getVersion();
    response.send(data);
});

redirectDeprecatedEndpoints(app);
setupPrivateEndpoints(app);

/**
 * Tasks that need to be run before the server starts listening.
 * @returns {Promise<void>}
 */
async function preSetupTasks() {
    const version = await getVersion();

    // Print formatted header
    console.log();
    console.log(`SillyTavern ${version.pkgVersion}`);
    if (version.gitBranch) {
        console.log(`Running '${version.gitBranch}' (${version.gitRevision}) - ${version.commitDate}`);
        if (!version.isLatest && ['staging', 'release'].includes(version.gitBranch)) {
            console.log('INFO: Currently not on the latest commit.');
            console.log('      Run \'git pull\' to update. If you have any merge conflicts, run \'git reset --hard\' and \'git pull\' to reset your branch.');
        }
    }
    console.log();

    const directories = await getUserDirectoriesList();
    await checkForNewContent(directories);
    await ensureThumbnailCache();
    cleanUploads();
    migrateAccessLog();

    await settingsInit();
    await statsInit();

    const pluginsDirectory = path.join(serverDirectory, 'plugins');
    const cleanupPlugins = await loadPlugins(app, pluginsDirectory);
    const consoleTitle = process.title;

    let isExiting = false;
    const exitProcess = async () => {
        if (isExiting) return;
        isExiting = true;
        await statsOnExit();
        if (typeof cleanupPlugins === 'function') {
            await cleanupPlugins();
        }
        setWindowTitle(consoleTitle);
        process.exit();
    };

    // Set up event listeners for a graceful shutdown
    process.on('SIGINT', exitProcess);
    process.on('SIGTERM', exitProcess);
    process.on('uncaughtException', (err) => {
        console.error('Uncaught exception:', err);
        exitProcess();
    });

    // Add request proxy.
    initRequestProxy({ enabled: cliArgs.requestProxyEnabled, url: cliArgs.requestProxyUrl, bypass: cliArgs.requestProxyBypass });

    // Wait for frontend libs to compile
    await webpackMiddleware.runWebpackCompiler();
}

/**
 * Tasks that need to be run after the server starts listening.
 * @param {import('./src/server-startup.js').ServerStartupResult} result The result of the server startup
 * @returns {Promise<void>}
 */
async function postSetupTasks(result) {
    const autorunHostname = await cliArgs.getAutorunHostname(result);
    const autorunUrl = cliArgs.getAutorunUrl(autorunHostname);

    if (cliArgs.autorun) {
        console.log('Launching in a browser...');
        await open(autorunUrl.toString());
    }

    setWindowTitle('SillyTavern WebServer');

    let logListen = 'SillyTavern is listening on';

    if (result.useIPv6 && !result.v6Failed) {
        logListen += color.green(
            ' IPv6: ' + cliArgs.getIPv6ListenUrl().host,
        );
    }

    if (result.useIPv4 && !result.v4Failed) {
        logListen += color.green(
            ' IPv4: ' + cliArgs.getIPv4ListenUrl().host,
        );
    }

    const goToLog = 'Go to: ' + color.blue(autorunUrl) + ' to open SillyTavern';
    const plainGoToLog = removeColorFormatting(goToLog);

    console.log(logListen);
    if (cliArgs.listen) {
        console.log();
        console.log('To limit connections to internal localhost only ([::1] or 127.0.0.1), change the setting in config.yaml to "listen: false".');
        console.log('Check the "access.log" file in the data directory to inspect incoming connections:', color.green(getAccessLogPath()));
    }
    console.log('\n' + getSeparator(plainGoToLog.length) + '\n');
    console.log(goToLog);
    console.log('\n' + getSeparator(plainGoToLog.length) + '\n');

    setupLogLevel();
    serverEvents.emit(EVENT_NAMES.SERVER_STARTED, { url: autorunUrl });
}

/**
 * Registers a not-found error response if a not-found error page exists. Should only be called after all other middlewares have been registered.
 */
function apply404Middleware() {
    const notFoundWebpage = safeReadFileSync('./public/error/url-not-found.html') ?? '';
    app.use((req, res) => {
        res.status(404).send(notFoundWebpage);
    });
}

// User storage module needs to be initialized before starting the server
initUserStorage(globalThis.DATA_ROOT)
    .then(ensurePublicDirectoriesExist)
    .then(migrateUserData)
    .then(migrateSystemPrompts)
    .then(verifySecuritySettings)
    .then(preSetupTasks)
    .then(apply404Middleware)
    .then(() => new ServerStartup(app, cliArgs).start())
    .then(postSetupTasks);
