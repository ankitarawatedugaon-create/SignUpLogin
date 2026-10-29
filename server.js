
require('dotenv').config();

const express = require('express');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 5000;

app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Login Signup API is running'
    });
});


const bcrypt = require('bcrypt');
const db = require('./db');

// POST - Register a new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // 1. Validate input
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Name, email and password are required'
            });
        }

        // 2. Check password length
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters'
            });
        }

        // 3. Check if email already exists
        const sql = 'SELECT id FROM users WHERE email = ?';

        db.query(sql, [email.trim().toLowerCase()], async (err, result) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Database error'
                });
            }

            if (result.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Email already registered'
                });
            }

            // 4. Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // 5. Insert user into MySQL
            const insertSql = `
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
            `;

            const values = [
                name.trim(),
                email.trim().toLowerCase(),
                hashedPassword
            ];

            db.query(insertSql, values, (err, insertResult) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(409).json({
                            success: false,
                            message: 'Email already registered'
                        });
                    }

                    return res.status(500).json({
                        success: false,
                        message: 'Could not register user'
                    });
                }

                // 6. Send success response
                return res.status(201).json({
                    success: true,
                    message: 'User registered successfully',
                    user: {
                        id: insertResult.insertId,
                        name: name.trim(),
                        email: email.trim().toLowerCase()
                    }
                });
            });
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});



const jwt = require('jsonwebtoken');

// POST - Login user
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    // 1. Validate input
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required'
        });
    }

    // 2. Find user by email
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email.trim().toLowerCase()], async (err, result) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: 'Database error'
            });
        }

        // 3. Check if user exists
        if (result.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const user = result[0];

        try {
            // 4. Compare password with stored hash
            const isMatch = await bcrypt.compare(
                password,
                user.password
            );

            if (!isMatch) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }

            // 5. Generate JWT token
            const token = jwt.sign(
                {
                    id: user.id,
                    email: user.email
                },
                process.env.JWT_SECRET,
                { expiresIn: '1d' }
            );

            // 6. Send response
            return res.status(200).json({
                success: true,
                message: 'Login successful',
                token: token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email
                }
            });
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: 'Login failed'
            });
        }
    });
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

require('./db');













// express =>	API aur routes banane ke liye
// mysql2 => MySQL database connect karne ke liye
// bcrypt => Password ko hash karke securely store karne ke liye
// jsonwebtoken =>	Login ke baad JWT token generate karne ke liye
// dotenv =>	Password aur secret keys ko .env file mein rakhne ke liye
// nodemon =>	Code change hone par server restart karne ke liye