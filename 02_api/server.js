const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

const SECRET_KEY = 'clave_secreta_actividad4_ciberseguridad';

// Usuario de prueba (contraseña real: "Passw0rd123")
const usuarios = [
  {
    id: 1,
    username: 'cesar',
    // Hash generado con bcrypt para "Passw0rd123"
    password: bcrypt.hashSync('Passw0rd123', 10)
  }
];

// --- Rate limiting: máximo 100 solicitudes por minuto por IP ---
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta de nuevo en un minuto.' }
});
app.use(limiter);

// --- Validación de entradas en /login ---
const validarLogin = [
  body('username')
    .trim()
    .notEmpty().withMessage('El usuario es obligatorio')
    .isAlphanumeric().withMessage('El usuario solo puede contener letras y números'),
  body('password')
    .trim()
    .notEmpty().withMessage('La contraseña es obligatoria')
    .isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
];

// --- POST /login ---
app.post('/login', validarLogin, (req, res) => {
  const errores = validationResult(req);
  if (!errores.isEmpty()) {
    return res.status(400).json({ errores: errores.array() });
  }

  const { username, password } = req.body;
  const usuario = usuarios.find(u => u.username === username);

  if (!usuario || !bcrypt.compareSync(password, usuario.password)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  const token = jwt.sign(
    { id: usuario.id, username: usuario.username },
    SECRET_KEY,
    { expiresIn: '1h' }
  );

  res.json({ mensaje: 'Login exitoso', token });
});

// --- Middleware para proteger rutas con JWT ---
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1]; // formato: "Bearer <token>"
  if (!token) {
    return res.status(401).json({ error: 'Formato de token inválido' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.usuario = decoded;
    next();
  });
}

// --- GET /perfil (endpoint protegido) ---
app.get('/perfil', verificarToken, (req, res) => {
  res.json({
    mensaje: 'Acceso autorizado',
    usuario: req.usuario
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});