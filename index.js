require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const Product = require('./models/product.model.js');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static('public')); // Serve static files from the public directory

// Connect to MongoDB
const mongoURI = process.env.MONGO_URI;
mongoose.connect(mongoURI)
    .then(() => {
        console.log('Connected to database!');
        app.listen(3000, () => {
            console.log('Server is running on port 3000');
        });
    })
    .catch((err) => {
        console.error('Connection to database failed:', err);
    });

// Google OAuth 2.0 setup
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.REDIRECT_URI);

const generateTokens = (payload) => {
    const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30m' });
    const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '1y' });
    return { accessToken, refreshToken };
};

// Middleware to verify access token
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });
        req.user = decoded;
        next();
    });
};

// Middleware to track and enforce rate limits
const hitTracker = {};
const rateLimiterMiddleware = (req, res, next) => {
    const customer_name = req.body.customer_name;
    const now = Date.now();

    // Clean up hitTracker: Remove entries older than 5 minutes
    for (const name in hitTracker) {
        hitTracker[name] = hitTracker[name].filter(timestamp => now - timestamp <= 5 * 60 * 1000);
        if (hitTracker[name].length === 0) delete hitTracker[name];
    }

    // Check if any customer has exceeded the limit of 2 hits in 5 minutes
    const customerHits = Object.keys(hitTracker).filter(name => hitTracker[name].length >= 2);
    if (customerHits.length >= 2) {
        return res.status(429).json({ message: 'Maximum limit exceeded (2 hits per 5 minutes)' });
    }

    // Check if the specific customer_name has exceeded the limit of 1 hit per 2 minutes
    if (hitTracker[customer_name] && hitTracker[customer_name].length >= 1) {
        return res.status(429).json({ message: 'Maximum limit exceeded (1 hit per 2 minutes)' });
    }

    // Track the hit
    if (!hitTracker[customer_name]) {
        hitTracker[customer_name] = [];
    }
    hitTracker[customer_name].push(now);

    // Proceed to the next middleware or route handler
    next();
};

// Middleware to restrict API based on time
const timeRestrictionMiddleware = (req, res, next) => {
    const now = new Date();
    const dayOfWeek = now.getDay(); // Sunday is 0, Monday is 1, ..., Saturday is 6
    const hours = now.getHours();

    // Check if it's Monday (0) or between 8:00 AM (8) and 3:00 PM (15)
    if (dayOfWeek === 1) {
        return res.status(403).json({ message: 'Please do not use this API on Monday' });
    }
    if (hours >= 8 && hours < 12) {
        return res.status(403).json({ message: 'Restricted time: Please try after 3pm' });
    }

    next();
};

// Helper function to calculate age
function calculateAge(dob) {
    const today = new Date();
    const birthDate = new Date(dob);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }

    return age;
}

// Google OAuth 2.0 routes
app.get('/auth/google', (req, res) => {
    const url = client.generateAuthUrl({
        access_type: 'offline',
        scope: ['profile', 'email']
    });
    res.redirect(url);
});

app.post('/auth/google/callback', async (req, res) => {
    try {
        const { id_token } = req.body;
        const ticket = await client.verifyIdToken({
            idToken: id_token,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();
        const tokensPair = generateTokens({ userId: payload.sub });

        res.json(tokensPair);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Token refresh route
app.post('/auth/refresh', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });

        const newTokens = generateTokens({ userId: decoded.userId });
        res.json(newTokens);
    });
});

// API endpoints
app.post('/db-save', authenticate, rateLimiterMiddleware, async (req, res) => {
    try {
        const { name, dob, income } = req.body;

        // Validate dob (optional)
        const age = calculateAge(dob);
        if (age <= 15) {
            return res.status(400).json({ message: 'Age must be greater than 15.' });
        }

        // Create the product
        const product = await Product.create({
            name,
            dob: new Date(dob),
            income
        });

        res.status(200).json(product);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/time-based-api', timeRestrictionMiddleware, async (req, res) => {
    try {
        const { name, dob, income } = req.body;

        // Create the product
        const product = await Product.create({
            name,
            dob: new Date(dob),
            income
        });

        res.status(200).json(product);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/db-search', async (req, res) => {
    try {
        const startTime = new Date(); // Start time of API request

        // Calculate birth year for age range calculation
        const today = new Date();
        const maxBirthYear = today.getFullYear() - 10;
        const minBirthYear = today.getFullYear() - 25;

        // Find customers whose age is between 10 and 25
        const customers = await Product.find({
            dob: {
                $gte: new Date(minBirthYear, 0, 1), // January 1st of (current year - 25)
                $lte: new Date(maxBirthYear, 11, 31) // December 31st of (current year - 10)
            }
        });

        const endTime = new Date(); // End time of API request
        const executionTime = (endTime - startTime) / 1000; // Execution time in seconds

        // Extract customer names from the query results
        const customerNames = customers.map(customer => customer.name);

        // Prepare response with customer names and execution time
        const response = {
            customer_names: customerNames,
            execution_time_seconds: executionTime
        };

        res.status(200).json(response);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Default route
app.get('/', (req, res) => {
    res.send("Hello from Node API Server");
});

// Error handling middleware
app.use((err, req, res, next) => {
    if (err.message === 'Maximum limit exceeded (1 hit per 2 minutes)' || err.message === 'Maximum limit exceeded (2 hits per 5 minutes)') {
        res.status(429).json({ message: err.message });
    } else {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
