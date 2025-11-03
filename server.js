// Load environment variables (like DATABASE_URL)
require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // Use 'bcrypt' for the non-deprecated library

// ----------------------------------------------------
// 1. PRISMA SETUP (Database Client)
// ----------------------------------------------------
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const app = express();
const PORT = 3000;

// IMPORTANT: Use environment variable for JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_12345'; 

// Middleware
app.use(cors()); // CORS fix is correctly applied here
app.use(express.json()); // Allows parsing of JSON request bodies

// ----------------------------------------------------
// CRITICAL HELPER: Map Prisma fields to Flutter fields
// ----------------------------------------------------

/**
 * Maps a single Prisma Task object (using 'isDone') to a Flutter Task object (using 'completed').
 * @param {Object} task - Prisma Task object
 * @returns {Object} - Flutter compatible Task object
 */
const mapPrismaToFlutter = (task) => {
    if (!task) return task;

    // Destructure isDone and collect the rest of the properties
    const { isDone, ...rest } = task;

    return {
        ...rest,
        // CRITICAL FIX: Map 'isDone' (Prisma) to 'completed' (Flutter)
        completed: isDone,
    };
};


// ----------------------------------------------------
// 2. AUTHENTICATION MIDDLEWARE
// ----------------------------------------------------

/**
 * Middleware to verify a JWT token in the request header and attach the user ID to the request.
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.error("Authentication Error: Token missing.");
        return res.status(401).json({ error: 'Unauthorized: Token missing.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Authentication Error: Invalid token or expired.", err);
            // Force logout on the client side if the status is 403/401
            return res.status(403).json({ error: 'Forbidden: Invalid or expired token.' });
        }
        // Attach the user's ID (e.g., 1) from the database to the request.
        req.userId = user.userId; 
        next();
    });
};

// ----------------------------------------------------
// 3. AUTH ROUTES (Register & Login)
// ----------------------------------------------------

// Route to register a new user
app.post('/api/register', async (req, res) => {
    if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ error: 'Request body missing or invalid JSON format.' });
    }
    
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Please provide username, email, and password.' });
    }

    try {
        // Check for existing user first (P2002 handles the unique constraint, but this provides a clearer error message)
        const existingUser = await prisma.user.findFirst({
            where: { OR: [{ username: username }, { email: email }] }
        });

        if (existingUser) {
            return res.status(409).json({ error: 'User with this username or email already exists.' });
        }
        
        const passwordHash = await bcrypt.hash(password, 10); 

        const newUser = await prisma.user.create({
            data: {
                username,
                email,
                passwordHash,
            },
        });

        // The userId payload for JWT must match the ID type (usually Int)
        const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({ 
            message: 'User registered successfully',
            token,
            user: { id: newUser.id, username: newUser.username, email: newUser.email }
        });
    } catch (error) {
        // P2002 error code is for unique constraint violation, which is handled above for clearer message.
        console.error('Registration Error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Route to log in an existing user
app.post('/api/login', async (req, res) => {
    if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ error: 'Request body missing or invalid JSON format.' });
    }
    
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

        const isValidPassword = await bcrypt.compare(password, user.passwordHash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // The userId payload for JWT must match the ID type (usually Int)
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

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

// This is the correct foreign key field name based on your schema
const TASK_USER_FOREIGN_KEY = 'authorId'; 

// GET all tasks for the authenticated user (READ)
app.get('/api/tasks', async (req, res) => {
    const authorId = parseInt(req.userId);
    
    try {
        const tasks = await prisma.task.findMany({
            where: { [TASK_USER_FOREIGN_KEY]: authorId }, 
            orderBy: [
                { isDone: 'asc' }, // Order incomplete tasks first
                { id: 'asc' }, 
            ],
        });
        
        // CRITICAL FIX: Map the results before sending to use 'completed'
        const flutterTasks = tasks.map(mapPrismaToFlutter);

        res.status(200).json(flutterTasks);
    } catch (error) {
        console.error('Fetch Tasks Error:', error);
        res.status(500).json({ error: 'Failed to fetch tasks.' });
    }
});

// POST a new task for the authenticated user (CREATE)
app.post('/api/tasks', async (req, res) => {
    const authorId = parseInt(req.userId);
    const { title } = req.body;

    if (!title || title.trim() === '') {
        return res.status(400).json({ error: 'Task title is required.' });
    }

    try {
        const newTask = await prisma.task.create({
            data: {
                title,
                [TASK_USER_FOREIGN_KEY]: authorId, 
                isDone: false, 
            },
        });
        
        // CRITICAL FIX: Map the result before sending to use 'completed'
        res.status(201).json(mapPrismaToFlutter(newTask));
    } catch (error) {
        console.error('Create Task Error:', error);
        res.status(500).json({ error: 'Failed to create task.' });
    }
});

// PUT/UPDATE an existing task (UPDATE)
app.put('/api/tasks/:id', async (req, res) => {
    const authorId = parseInt(req.userId);
    const taskId = parseInt(req.params.id);
    
    // CRITICAL FIX: Accept 'completed' from Flutter body. Also accept 'isDone' for flexibility.
    const { title, isDone: isDoneBody, completed } = req.body; 

    if (isNaN(taskId)) {
        return res.status(400).json({ error: 'Invalid task ID.' });
    }
    
    const updateData = {};
    if (title !== undefined && title !== null) {
        if (title.trim() === '') {
            return res.status(400).json({ error: 'Task title cannot be empty.' });
        }
        updateData.title = title;
    }
    
    // Map incoming 'completed' (Flutter) to 'isDone' (Prisma)
    if (completed !== undefined && completed !== null) {
        updateData.isDone = completed; 
    } else if (isDoneBody !== undefined && isDoneBody !== null) {
        // Allow isDone for non-Flutter clients (like Postman)
        updateData.isDone = isDoneBody;
    }
    
    if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ error: 'Must provide title or completed status for update.' });
    }

    try {
        const updatedTaskResult = await prisma.task.updateMany({
            where: {
                id: taskId,
                [TASK_USER_FOREIGN_KEY]: authorId, // Match task to user
            },
            data: updateData,
        });

        if (updatedTaskResult.count === 0) {
            return res.status(404).json({ error: 'Task not found or unauthorized.' });
        }
        
        // Fetch the updated task to return the full object
        const task = await prisma.task.findUnique({ where: { id: taskId } });
        
        // CRITICAL FIX: Map the result before sending to use 'completed'
        res.status(200).json(mapPrismaToFlutter(task));

    } catch (error) {
        console.error('Update Task Error:', error);
        res.status(500).json({ error: 'Failed to update task.' });
    }
});

// DELETE a task (DELETE)
app.delete('/api/tasks/:id', async (req, res) => {
    const authorId = parseInt(req.userId);
    const taskId = parseInt(req.params.id);

    if (isNaN(taskId)) {
        return res.status(400).json({ error: 'Invalid task ID.' });
    }

    try {
        const deletedTask = await prisma.task.deleteMany({
            where: {
                id: taskId,
                [TASK_USER_FOREIGN_KEY]: authorId, // Match task to user
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
        await prisma.$connect();
        console.log("✅ Database connection successful!");

        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}...`);
            console.log(`API URL: http://localhost:${PORT}`);
        });

    } catch (error) {
        console.error("❌ FATAL ERROR: Database connection failed.");
        console.error("Please check your DATABASE_URL in the .env file and ensure the database is running.");
        console.error(error);
        process.exit(1); 
    }
}

// Call the function to start the process
connectToDatabaseAndStartServer();
