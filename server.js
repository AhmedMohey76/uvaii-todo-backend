// Load environment variables (like DATABASE_URL)
require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// ----------------------------------------------------
// 1. PRISMA SETUP (Database Client)
// ----------------------------------------------------
// Note: PrismaClient automatically uses the DATABASE_URL
// from the .env file to connect to your SQLite (dev.db) database.
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const app = express();
const PORT = 3000;

// IMPORTANT: Replace this with a strong, secret key for production
const JWT_SECRET = 'your_super_secret_jwt_key_12345'; 

// Middleware
app.use(cors());
app.use(express.json()); // Allows parsing of JSON request bodies

// ----------------------------------------------------
// 2. AUTHENTICATION MIDDLEWARE
// ----------------------------------------------------

/**
 * Middleware to verify a JWT token in the request header and attach the user ID to the request.
 */
const authenticateToken = (req, res, next) => {
    // Get token from the Authorization header (Format: Bearer TOKEN)
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.sendStatus(401); // Unauthorized if no token
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden if token is invalid or expired
        }
        // Attach the user's ID (which is stored in the token payload) to the request
        req.userId = user.userId; 
        next();
    });
};

// ----------------------------------------------------
// 3. AUTH ROUTES (Register & Login)
// ----------------------------------------------------

// Route to register a new user
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    // Simple input validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Please provide username, email, and password.' });
    }

    try {
        // Hash the password before saving it to the database
        const passwordHash = await bcrypt.hash(password, 10); 

        const newUser = await prisma.user.create({
            data: {
                username,
                email,
                passwordHash,
            },
        });

        // Generate JWT token upon successful registration
        const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ 
            message: 'User registered successfully',
            token,
            user: { id: newUser.id, username: newUser.username, email: newUser.email }
        });
    } catch (error) {
        // Handle duplicate email error
        if (error.code === 'P2002') {
            return res.status(409).json({ error: 'Email address already in use.' });
        }
        console.error('Registration Error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Route to log in an existing user
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Please provide email and password.' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Compare the provided password with the hashed password in the database
        const isValidPassword = await bcrypt.compare(password, user.passwordHash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Generate JWT token upon successful login
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Login successful',
            token,
            user: { id: user.id, username: user.username, email: user.email }
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});


// ----------------------------------------------------
// 4. TASK ROUTES (Protected by Authentication)
// ----------------------------------------------------

// Middleware is applied to all task routes to ensure the user is logged in
app.use('/api/tasks', authenticateToken);


// GET all tasks for the authenticated user
app.get('/api/tasks', async (req, res) => {
    const userId = req.userId; // Retrieved from the JWT token via middleware
    
    try {
        const tasks = await prisma.task.findMany({
            where: { authorId: userId },
            orderBy: {
                id: 'asc', // Sort by creation order
            },
        });
        res.status(200).json(tasks);
    } catch (error) {
        console.error('Fetch Tasks Error:', error);
        res.status(500).json({ error: 'Failed to fetch tasks.' });
    }
});

// POST a new task for the authenticated user
app.post('/api/tasks', async (req, res) => {
    const userId = req.userId;
    const { title } = req.body;

    if (!title) {
        return res.status(400).json({ error: 'Task title is required.' });
    }

    try {
        const newTask = await prisma.task.create({
            data: {
                title,
                authorId: userId,
            },
        });
        res.status(201).json(newTask);
    } catch (error) {
        console.error('Create Task Error:', error);
        res.status(500).json({ error: 'Failed to create task.' });
    }
});

// PUT/UPDATE an existing task
app.put('/api/tasks/:id', async (req, res) => {
    const userId = req.userId;
    const taskId = parseInt(req.params.id);
    const { title, completed } = req.body;

    try {
        // Update task, but only if it belongs to the authenticated user
        const updatedTask = await prisma.task.updateMany({
            where: {
                id: taskId,
                authorId: userId,
            },
            data: {
                title: title,
                completed: completed,
            },
        });

        if (updatedTask.count === 0) {
            return res.status(404).json({ error: 'Task not found or unauthorized.' });
        }
        
        // Fetch the updated task to return the full object
        const task = await prisma.task.findUnique({ where: { id: taskId } });
        res.status(200).json(task);

    } catch (error) {
        console.error('Update Task Error:', error);
        res.status(500).json({ error: 'Failed to update task.' });
    }
});

// DELETE a task
app.delete('/api/tasks/:id', async (req, res) => {
    const userId = req.userId;
    const taskId = parseInt(req.params.id);

    try {
        // Delete task, but only if it belongs to the authenticated user
        const deletedTask = await prisma.task.deleteMany({
            where: {
                id: taskId,
                authorId: userId,
            },
        });

        if (deletedTask.count === 0) {
            return res.status(404).json({ error: 'Task not found or unauthorized.' });
        }

        res.status(200).json({ message: 'Task deleted successfully.' });

    } catch (error) {
        console.error('Delete Task Error:', error);
        res.status(500).json({ error: 'Failed to delete task.' });
    }
});

// ----------------------------------------------------
// 5. START SERVER
// ----------------------------------------------------

// Simple status route
app.get('/', (req, res) => {
    res.send('Todo List API Server is running and connected to database.');
});

/**
 * Checks the database connection by trying to connect and disconnect.
 * If successful, starts the Express server.
 */
async function connectToDatabaseAndStartServer() {
    try {
        // This command forces Prisma to connect to the database and ensures it's reachable.
        await prisma.$connect();
        console.log("✅ Database connection successful!");

        // Start the server only if the database connection succeeds
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}...`);
            console.log(`API URL: http://localhost:${PORT}`);
        });

    } catch (error) {
        console.error("❌ FATAL ERROR: Database connection failed.");
        console.error("Please check your DATABASE_URL in the .env file and ensure the database is running.");
        console.error(error);
        // Exit the process if the database cannot be reached
        process.exit(1); 
    }
}

// Call the function to start the process
connectToDatabaseAndStartServer();
