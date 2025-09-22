// server/routes/auth.js
// require('dotenv').config(); // Hapus baris ini jika sudah di app.js, atau ubah ke import jika ini entry point
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../db.js'; // Pastikan ada .js
import { v4 as uuidv4 } from 'uuid';

const router = express.Router();

// Rute untuk registrasi (Sign Up)
router.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password harus diisi.' });
    }

    try {
        const [existingUsers] = await db.execute('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username sudah terdaftar.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();

        await db.execute('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)', [userId, username, hashedPassword]);
        res.status(201).json({ message: 'Pendaftaran berhasil!', userId: userId });
    } catch (error) {
        console.error('Error during sign up:', error);
        res.status(500).json({ message: 'Terjadi kesalahan server saat pendaftaran.' });
    }
});

// Rute untuk Login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password harus diisi.' });
    }

    try {
        const [users] = await db.execute('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }

        const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login berhasil!', token: token, userId: user.id, username: user.username });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Terjadi kesalahan server saat login.' });
    }
});

export default router; // Perubahan di sini: Menggunakan export default