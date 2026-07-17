const http = require('http');
const url = require('url');

// Server configuration constants
const PORT = 3000;
const HOST = '127.0.0.1';

// Sample in-memory user store
const users = [
    { id: 1, name: 'Alice Smith', role: 'admin' },
    { id: 2, name: 'Bob Johnson', role: 'user' },
    { id: 3, name: 'Charlie Brown', role: 'guest' }
];

// Helper to log server actions
function logRequest(req) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} requested for URL: ${req.url}`);
}

// Request dispatcher / router
function handleRoutes(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');

    if (pathname === '/' || pathname === '/index') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<h1>Welcome to AntiGravity Simulation Node Server</h1><p>Running healthy.</p>');
    } 
    else if (pathname === '/api/users' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(users));
    } 
    else if (pathname.startsWith('/api/users/') && req.method === 'GET') {
        const parts = pathname.split('/');
        const userId = parseInt(parts[parts.length - 1], 10);
        const user = users.find(u => u.id === userId);

        if (user) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(user));
        } else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'User not found' }));
        }
    } 
    else if (pathname === '/api/status' && req.method === 'GET') {
        const statusReport = {
            status: 'UP',
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            timestamp: Date.now()
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(statusReport));
    } 
    else if (pathname === '/api/echo' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ received: body, status: 'echoed' }));
        });
    } 
    else {
        // Fallback for page not found
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Error 404: Resource Not Found');
    }
}

// Server creation and initiation
const server = http.createServer((req, res) => {
    logRequest(req);
    try {
        handleRoutes(req, res);
    } catch (error) {
        console.error('Routing error:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
    }
});

// Startup listener
server.listen(PORT, HOST, () => {
    console.log(`========================================`);
    console.log(`Server is running at http://${HOST}:${PORT}`);
    console.log(`Press Ctrl+C to terminate the process.`);
    console.log(`========================================`);
});
