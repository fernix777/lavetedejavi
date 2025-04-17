// Adaptación mínima de login y ruta protegida para Vercel Serverless
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';

const JWT_SECRET = process.env.JWT_SECRET || 'secreto_desarrollo';
const app = express();
const db = new sqlite3.Database('tienda.db');

app.use(express.json());
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(cookieParser());

const autenticarJWT = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'no_autorizado', mensaje: 'No se proporcionó token de autenticación' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'token_invalido', mensaje: 'El token de autenticación es inválido' });
    }
    req.user = user;
    next();
  });
};

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM usuarios WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'database_error' });
    if (!user) {
      return res.status(401).json({ error: 'credenciales_invalidas', mensaje: 'Usuario no encontrado' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'credenciales_invalidas', mensaje: 'Contraseña incorrecta' });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, rol: user.rol },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
      maxAge: 3600000
    });
    res.json({ 
      message: 'Login exitoso', 
      access_token: token,
      user: { id: user.id, username: user.username, rol: user.rol }
    });
  });
});

app.get('/api/protected', autenticarJWT, (req, res) => {
  res.json({ 
    username: req.user.username,
    rol: req.user.rol
  });
});

// Adaptador para Vercel
import { createServer } from 'http';
import { parse } from 'url';

const server = createServer((req, res) => {
  const parsedUrl = parse(req.url, true);
  app(req, res);
});

export default server;
