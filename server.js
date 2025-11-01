const express = require('express');
const cors = require('cors'); // Import CORS package
const app = express();
const PORT = 3000;

// Middleware: Enable CORS for all origins. This is necessary for Flutter web (Chrome) 
// to connect to a server running on the same machine.
app.use(cors());

// Hardcoded JSON Data
const hardcodedUsers = [
  { id: 101, username: 'Alice', role: 'Tester' },
  { id: 102, username: 'Bob', role: 'Developer' },
  { id: 103, username: 'Charlie', role: 'Admin' },
];

// Route 1: Root path (/)
app.get('/', (req, res) => {
  res.send('Welcome to the Warm-up Backend API! Access /api/test/users for data.');
});

// Route 2: The Warm-up Data Endpoint
app.get('/api/test/users', (req, res) => {
  console.log('GET request received for /api/test/users');
  // Send the hardcoded JSON data
  res.json(hardcodedUsers);
});


// Start the server
app.listen(PORT, () => {
  console.log(`Backend server listening at http://localhost:${PORT}`);
});
