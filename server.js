// =========================
// CONFIGURACIÓN Y SEGURIDAD
// =========================
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import { readFileSync } from 'fs';
import multer from 'multer';
import path from 'path';

// Cargar variables de entorno (puedes usar dotenv si lo deseas)
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_desarrollo';

const app = express();
const db = new sqlite3.Database('tienda.db', (err) => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    process.exit(1);
  }
  console.log('Conexión exitosa con la base de datos SQLite');
  
  // Verificar que las tablas existan
  db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'", [], (err, row) => {
    if (err) {
      console.error('Error al verificar las tablas:', err);
      process.exit(1);
    }
    if (!row) {
      console.log('Iniciando creación de tablas...');
      // Leer y ejecutar el schema SQL
      try {
        const schema = readFileSync('schema.sql', 'utf8');
        db.exec(schema, (err) => {
          if (err) {
            console.error('Error al crear las tablas:', err);
            process.exit(1);
          }
          console.log('Tablas creadas exitosamente');
        });
      } catch (err) {
        console.error('Error al leer el archivo schema.sql:', err);
        process.exit(1);
      }
    }
  });
});

// Middleware de seguridad adicional
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// =========================
// MIDDLEWARES Y ARCHIVOS ESTÁTICOS
// =========================
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  exposedHeaders: ['Set-Cookie']
}));
app.use(cookieParser());

// Limitar archivos estáticos solo a carpetas públicas
app.use('/images', express.static('images'));
app.use('/css', express.static('css'));
app.use('/js', express.static('js'));

// Servir archivos HTML estáticos desde la raíz
app.use(express.static('.'));

// =========================
// CONFIGURACIÓN DE MULTER
// =========================
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'images/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '-'))
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Solo se permiten archivos de imagen'));
    }
});

// =========================
// AUTENTICACIÓN Y UTILIDADES
// =========================
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

// =========================
// RUTAS PRINCIPALES
// =========================
// Ruta raíz
app.get('/', (req, res) => {
  res.sendFile('index.html', { root: '.' });
});

// Ruta de login
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
    
    // Agregar el id al token JWT
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

// Ruta protegida de ejemplo
app.get('/api/protected', autenticarJWT, (req, res) => {
  res.json({ 
    username: req.user.username,
    rol: req.user.rol
  });
});

// Rutas de productos
app.post('/api/productos', autenticarJWT, (req, res) => {
    const { nombre, codigo_barras, categoria_id, stock, precio_costo, precio_venta } = req.body;
    
    if (!nombre || !codigo_barras || !categoria_id || stock === undefined || !precio_costo || !precio_venta) {
        return res.status(400).json({ error: 'datos_invalidos', mensaje: 'Todos los campos son requeridos' });
    }

    const query = `
        INSERT INTO productos (
            nombre, 
            codigo_barras, 
            categoria_id, 
            stock, 
            precio_costo, 
            precio_venta
        ) VALUES (?, ?, ?, ?, ?, ?)
    `;
    
    db.run(query, [nombre, codigo_barras, categoria_id, stock, precio_costo, precio_venta], function(err) {
        if (err) {
            console.error('Error al crear producto:', err);
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ 
                    error: 'codigo_duplicado', 
                    mensaje: 'Ya existe un producto con ese código de barras' 
                });
            }
            return res.status(500).json({ error: 'error_database' });
        }
        res.status(201).json({ 
            id: this.lastID, 
            mensaje: 'Producto creado exitosamente',
            producto: {
                id: this.lastID,
                nombre,
                codigo_barras,
                categoria_id,
                stock,
                precio_costo,
                precio_venta
            }
        });
    });
});

app.get('/api/productos', autenticarJWT, (req, res) => {
    const query = `
        SELECT 
            p.*,
            c.nombre as categoria_nombre
        FROM productos p
        LEFT JOIN categorias c ON p.categoria_id = c.id
    `;
    
    db.all(query, [], (err, productos) => {
        if (err) {
            console.error('Error al obtener productos:', err);
            return res.status(500).json({ error: 'error_database' });
        }
        res.json(productos);
    });
});

app.put('/api/productos/:id', autenticarJWT, (req, res) => {
  const { nombre, codigo_barras, categoria_id, stock, precio_costo, precio_venta } = req.body;
  const { id } = req.params;

  if (!nombre || !codigo_barras || !categoria_id || stock === undefined || !precio_costo || !precio_venta) {
    return res.status(400).json({ error: 'datos_invalidos', mensaje: 'Todos los campos son requeridos' });
  }

  const query = `
    UPDATE productos 
    SET nombre = ?, codigo_barras = ?, categoria_id = ?, stock = ?, precio_costo = ?, precio_venta = ?
    WHERE id = ?
  `;

  db.run(query, [nombre, codigo_barras, categoria_id, stock, precio_costo, precio_venta, id], function(err) {
    if (err) return res.status(500).json({ error: 'error_database' });
    if (this.changes === 0) return res.status(404).json({ error: 'producto_no_encontrado' });
    res.json({ mensaje: 'Producto actualizado exitosamente' });
  });
});

app.delete('/api/productos/:id', autenticarJWT, (req, res) => {
  const { id } = req.params;

  db.run('DELETE FROM productos WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'error_database' });
    if (this.changes === 0) return res.status(404).json({ error: 'producto_no_encontrado' });
    res.json({ mensaje: 'Producto eliminado exitosamente' });
  });
});

// Ruta para subir imagen de producto
app.post('/api/productos/:id/imagen', autenticarJWT, upload.single('imagen'), (req, res) => {
    const { id } = req.params;
    
    if (!req.file) {
        return res.status(400).json({ error: 'No se subió ninguna imagen' });
    }

    const rutaImagen = '/images/' + req.file.filename;

    db.run('UPDATE productos SET imagen = ? WHERE id = ?', [rutaImagen, id], function(err) {
        if (err) {
            console.error('Error al actualizar imagen:', err);
            return res.status(500).json({ error: 'error_database' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'producto_no_encontrado' });
        }
        res.json({ 
            mensaje: 'Imagen actualizada correctamente',
            rutaImagen: rutaImagen
        });
    });
});

// Rutas de categorías
app.get('/api/categorias', autenticarJWT, (req, res) => {
  db.all('SELECT * FROM categorias', [], (err, categorias) => {
    if (err) return res.status(500).json({ error: 'error_database' });
    res.json(categorias);
  });
});

app.post('/api/categorias', autenticarJWT, (req, res) => {
  const { nombre, descripcion } = req.body;
  
  if (!nombre) {
    return res.status(400).json({ error: 'datos_invalidos' });
  }

  const query = 'INSERT INTO categorias (nombre, descripcion) VALUES (?, ?)';

  db.run(query, [nombre, descripcion], function(err) {
    if (err) return res.status(500).json({ error: 'error_database' });
    res.status(201).json({ id: this.lastID, mensaje: 'Categoría creada exitosamente' });
  });
});

app.put('/api/categorias/:id', autenticarJWT, (req, res) => {
  const { nombre, descripcion } = req.body;
  const { id } = req.params;

  if (!nombre) {
    return res.status(400).json({ error: 'datos_invalidos' });
  }

  const query = 'UPDATE categorias SET nombre = ?, descripcion = ? WHERE id = ?';

  db.run(query, [nombre, descripcion, id], function(err) {
    if (err) return res.status(500).json({ error: 'error_database' });
    if (this.changes === 0) return res.status(404).json({ error: 'categoria_no_encontrada' });
    res.json({ mensaje: 'Categoría actualizada exitosamente' });
  });
});

app.delete('/api/categorias/:id', autenticarJWT, (req, res) => {
  const { id } = req.params;

  // Primero verificamos si hay productos asociados a esta categoría
  db.get('SELECT COUNT(*) as count FROM productos WHERE categoria_id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'error_database' });
    
    if (result.count > 0) {
      return res.status(400).json({ error: 'categoria_con_productos' });
    }

    // Si no hay productos asociados, procedemos con la eliminación
    db.run('DELETE FROM categorias WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'error_database' });
      if (this.changes === 0) return res.status(404).json({ error: 'categoria_no_encontrada' });
      res.json({ mensaje: 'Categoría eliminada exitosamente' });
    });
  });
});

// Rutas de ventas
app.get('/api/ventas', autenticarJWT, (req, res) => {
    const { filtro } = req.query;
    let whereClause = '';
    // Construir la cláusula WHERE según el filtro
    if (filtro === 'hoy') {
        whereClause = "WHERE DATE(v.fecha) = DATE('now')";
    } else if (filtro === 'semana') {
        whereClause = "WHERE v.fecha >= date('now', '-7 days')";
    } else if (filtro === 'mes') {
        whereClause = "WHERE v.fecha >= date('now', '-1 month')";
    }
    const query = `
        SELECT v.*, u.username as vendedor
        FROM ventas v
        LEFT JOIN usuarios u ON v.usuario_id = u.id
        ${whereClause}
        ORDER BY v.fecha DESC
    `;
    db.all(query, [], (err, ventas) => {
        if (err) {
            console.error('Error en la consulta de ventas:', err);
            return res.status(500).json({ error: 'error_database' });
        }
        // Obtener detalles de cada venta
        const ventasConDetalles = [];
        let procesadas = 0;
        if (ventas.length === 0) return res.json([]);
        ventas.forEach(venta => {
            db.all(
                'SELECT producto_id, cantidad, precio, (cantidad * precio) as total FROM venta_detalles WHERE venta_id = ?',
                [venta.id],
                (err, detalles) => {
                    if (err) {
                        console.error('Error al obtener detalles de venta:', err);
                        venta.detalles = [];
                    } else {
                        venta.detalles = detalles;
                    }
                    // Calcular total real por si acaso
                    venta.total = detalles.reduce((sum, d) => sum + d.total, 0);
                    ventasConDetalles.push(venta);
                    procesadas++;
                    if (procesadas === ventas.length) {
                        res.json(ventasConDetalles);
                    }
                }
            );
        });
    });
});

app.post('/api/ventas', autenticarJWT, (req, res) => {
    const { productos, total, metodo_pago } = req.body;
    if (!productos || !Array.isArray(productos) || productos.length === 0 || !metodo_pago) {
      console.error('Datos inválidos en la venta:', req.body);
      return res.status(400).json({ error: 'datos_invalidos', mensaje: 'Productos o método de pago faltantes' });
    }
    if (!req.user || !req.user.id) {
      console.error('Usuario no autenticado o sin ID:', req.user);
      return res.status(401).json({ error: 'usuario_invalido', mensaje: 'Usuario no autenticado' });
    }
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      // Crear la venta
      db.run(
        'INSERT INTO ventas (usuario_id, fecha, total, metodo_pago) VALUES (?, datetime("now"), ?, ?)',
        [req.user.id, total, metodo_pago],
        function(err) {
          if (err) {
            db.run('ROLLBACK');
            console.error('Error al insertar venta:', err);
            return res.status(500).json({ error: 'error_database', mensaje: 'Error al insertar venta' });
          }
          const ventaId = this.lastID;
          let procesados = 0;
          let error = null;
          let errorMsg = '';
          if (productos.length === 0) {
            db.run('ROLLBACK');
            return res.status(400).json({ error: 'datos_invalidos', mensaje: 'No hay productos en la venta' });
          }
          productos.forEach(({ producto_id, cantidad, precio_unitario }) => {
            if (!producto_id || !cantidad || cantidad <= 0 || !precio_unitario) {
              error = 'datos_invalidos';
              errorMsg = 'Producto, cantidad o precio inválido';
              procesados++;
              if (procesados === productos.length) {
                db.run('ROLLBACK');
                return res.status(400).json({ error, mensaje: errorMsg });
              }
              return;
            }
            // Verificar stock y actualizar
            db.run(
              'UPDATE productos SET stock = stock - ? WHERE id = ? AND stock >= ?',
              [cantidad, producto_id, cantidad],
              function(err) {
                if (err) {
                  error = 'error_database';
                  errorMsg = 'Error de base de datos al actualizar stock';
                } else if (this.changes === 0) {
                  error = 'stock_insuficiente';
                  errorMsg = 'Stock insuficiente para el producto ' + producto_id;
                }
                if (error) {
                  procesados++;
                  if (procesados === productos.length) {
                    db.run('ROLLBACK');
                    return res.status(400).json({ error, mensaje: errorMsg });
                  }
                  return;
                }
                // Registrar detalle de venta
                db.run(
                  'INSERT INTO venta_detalles (venta_id, producto_id, cantidad, precio) VALUES (?, ?, ?, ?)',
                  [ventaId, producto_id, cantidad, precio_unitario],
                  (err) => {
                    if (err) {
                      error = 'error_database';
                      errorMsg = 'Error al insertar detalle de venta';
                    }
                    procesados++;
                    if (procesados === productos.length) {
                      if (error) {
                        db.run('ROLLBACK');
                        return res.status(500).json({ error, mensaje: errorMsg });
                      } else {
                        db.run('COMMIT');
                        return res.status(201).json({
                          id: ventaId,
                          mensaje: 'Venta registrada exitosamente'
                        });
                      }
                    }
                  }
                );
              }
            );
          });
        }
      );
    });
  });

// Rutas de facturación
app.post('/api/facturas/imprimir', autenticarJWT, (req, res) => {
    const { rfc, razonSocial, direccionFiscal, items, subtotal, descuentos, total } = req.body;
    
    // Aquí iría la lógica de conexión con la impresora
    // Por ahora solo simulamos la impresión
    console.log('Imprimiendo factura:', {
        rfc,
        razonSocial,
        direccionFiscal,
        items,
        subtotal,
        descuentos,
        total
    });

    res.json({ mensaje: 'Factura enviada a impresión' });
});

app.post('/api/facturas/email', autenticarJWT, (req, res) => {
    const { email, rfc, razonSocial, direccionFiscal, items, subtotal, descuentos, total } = req.body;
    
    // Aquí iría la lógica de envío de email
    // Por ahora solo simulamos el envío
    console.log('Enviando factura por email a:', email, {
        rfc,
        razonSocial,
        direccionFiscal,
        items,
        subtotal,
        descuentos,
        total
    });

    res.json({ mensaje: 'Factura enviada por email' });
});

// =========================
// INICIO DEL SERVIDOR
// =========================
app.listen(PORT, () => {
  console.log(`Servidor Express ejecutándose en http://localhost:${PORT}`);
});

// =========================
// NOTAS Y RECOMENDACIONES
// =========================
// - Usa variables de entorno para datos sensibles (puerto, JWT_SECRET, rutas de archivos).
// - No expongas archivos estáticos fuera de carpetas públicas.
// - Considera separar rutas y controladores en archivos distintos para mayor escalabilidad.
// - Implementa protección CSRF si agregas formularios críticos.
// - Revisa y mejora validaciones y mensajes de error en cada endpoint.
// - Documenta tu API y agrega tests automáticos si es posible.