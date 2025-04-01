const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const multer = require("multer");
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const path = require("path");
const axios = require('axios'); 
const WebSocket = require('ws');
const fs = require("fs");
const serviceAccount = JSON.parse(Buffer.from(process.env.FIREBASE_CREDENTIALS_BASE64, 'base64').toString('utf-8'));
// Inicializar Firebase
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://carcollection-c78ed-default-rtdb.firebaseio.com/",
  storageBucket: "carcollection-c78ed.appspot.com" // Nombre correcto del bucket
});

const bucket = admin.storage().bucket();
const db = admin.firestore();

const app = express();
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000", "https://dwp-frontend-carcoleccion.onrender.com"], // ✅ Permite solicitudes desde el frontend
  credentials: true,
  methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
  allowedHeaders: "Content-Type,Authorization"
}));

app.options("*", cors());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});


const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ intMessage: "Acceso denegado. Token requerido" });
  }

  jwt.verify(token.split(" ")[1], "claveSecreta", (err, decoded) => {
    if (err) {
      return res.status(401).json({ intMessage: "Token inválido o expirado" });
    }
    req.usuario = decoded;
    next();
  });
};

const handleError = (res, error, customMessage = "Error interno") => {
  console.error(customMessage, error);
  res.status(500).json({ intMessage: customMessage, error: error.message || error });
};

const getDocumentById = async (collection, id) => {
  const docRef = db.collection(collection).doc(id);
  const docSnap = await docRef.get();
  if (!docSnap.exists) throw new Error(`Documento con ID ${id} no encontrado`);
  return { id: docSnap.id, ...docSnap.data() };
};

// Configuración de multer para guardar imágenes
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tempPath = path.join(__dirname, "uploads", "temp");
    if (!fs.existsSync(tempPath)) {
      fs.mkdirSync(tempPath, { recursive: true });
    }
    cb(null, tempPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    const file = req.file;
    const fileUpload = await bucket.upload(file.path, {
      destination: `coleccionables/${file.filename}`
    });
    const publicUrl = `https://storage.googleapis.com/${bucket.name}/${fileUpload[0].name}`;
    
    // Hacer algo con publicUrl
    res.status(200).json({ url: publicUrl });
  } catch (error) {
    handleError(res, error, "Error al subir archivo");
  }
});

// Login -- 1 
app.post("/api/acceso", async (req, res) => {
  const { usuario, contra } = req.body;
  
  if (!usuario || !contra) {
    return res.status(400).json({ intMessage: "Faltan datos" });
  }
  
  try {
    const userSnapshot = await db.collection("Users").where("username", "==", usuario).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ intMessage: "Usuario no encontrado" });
    }

    const userData = userSnapshot.docs[0].data();
    const userId = userSnapshot.docs[0].id;
    const passwordMatch = await bcrypt.compare(contra, userData.password);

    if (!passwordMatch) {
      return res.status(401).json({ intMessage: "Contraseña incorrecta" });
    }
    
    // Si el usuario tiene MFA activado, requerir verificación
    if (userData.mfaEnabled) {
      return res.status(200).json({ 
        requiresMFA: true,
        tempToken: jwt.sign(
          { username: usuario, id: userId, mfaCheck: true },
          "claveSecreta",
          { expiresIn: "5m" } // Token temporal corto
        )
      });
    }
    
    // Si no tiene MFA, proceder como antes
    const token = jwt.sign(
      { username: usuario, rol: userData.rol, id: userId },
      "claveSecreta",
      { expiresIn: "10m" }
    );
    
    await userSnapshot.docs[0].ref.update({ last_login: new Date() });
    res.status(200).json({
      token,
      intMessage: "Bienvenido al sistema",
      data: { username: usuario, rol: userData.rol },
    });
  } catch (error) {
    handleError(res, error, "Error al iniciar sesión");
  }
});
//2
app.post("/api/acceso-mfa", async (req, res) => {
  const { tempToken, mfaToken } = req.body;
  
  try {
    // Verificar el token temporal
    const decoded = jwt.verify(tempToken, "claveSecreta");
    
    if (!decoded.mfaCheck) {
      return res.status(400).json({ intMessage: "Token inválido para MFA" });
    }
    
    // Obtener usuario
    const userDoc = await db.collection("Users").doc(decoded.id).get();
    if (!userDoc.exists) {
      return res.status(404).json({ intMessage: "Usuario no encontrado" });
    }
    
    const userData = userDoc.data();
    
    // Verificar código MFA
    const verified = speakeasy.totp.verify({
      secret: userData.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 1
    });
    
    if (!verified) {
      return res.status(401).json({ intMessage: "Código MFA inválido" });
    }
    
    // Generar token final
    const finalToken = jwt.sign(
      { username: decoded.username, rol: userData.rol, id: decoded.id },
      "claveSecreta",
      { expiresIn: "10m" }
    );
    
    res.status(200).json({
      token: finalToken,
      intMessage: "Bienvenido al sistema",
      data: { username: decoded.username, rol: userData.rol },
    });
  } catch (error) {
    handleError(res, error, "Error en verificación MFA");
  }
});

// Registro--3
app.post("/api/registro", async (req, res) => {
  const { usuario, correo, contra, nombre } = req.body;
  if (!usuario || !correo || !contra || !nombre) {
    return res.status(400).json({ intMessage: "Faltan datos" });
  }

  try {
    const userSnapshot = await db.collection("Users").where("username", "==", usuario).get();
    if (!userSnapshot.empty) {
      return res.status(400).json({ intMessage: "Usuario ya existe" });
    }
    
    const rol = "usuario";
    const hashPassword = await bcrypt.hash(contra, 10);
    
    // Generar secreto para MFA
    const secret = speakeasy.generateSecret({
      length: 20,
      name: encodeURIComponent(usuario), // Codificar caracteres especiales
      issuer: encodeURIComponent("CarCollection") // Nombre de tu app codificado
    });
    const otpauthUrl = secret.otpauth_url;
    
    const userRef = await db.collection("Users").add({
      username: usuario,
      email: correo,
      password: hashPassword,
      nombre: nombre,
      rol: rol,
      mfaSecret: secret.base32,
      mfaEnabled: false
    });
    
    // Crear una versión más corta de la URL para el QR
    const shortOtpUrl = `otpauth://totp/CarCol:${usuario}?secret=${secret.base32}&issuer=CarCol`;
    
    // Generar URL QR para la app de autenticación
    const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);
    
    res.status(201).json({ 
      intMessage: "Usuario registrado con éxito",
      mfaSetup: {
        secret: secret.base32,
        otpauthUrl: otpauthUrl, // Enviamos el URI completo
        qrCodeUrl: qrCodeUrl
      }
    });
  } catch (error) {
    handleError(res, error, "Error al registrar usuario");
  }
});

// Nuevo endpoint para verificar MFA--3
app.post("/api/verify-mfa", async (req, res) => {
  const { username, token } = req.body;
  
  try {
    const userSnapshot = await db.collection("Users").where("username", "==", username).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ intMessage: "Usuario no encontrado" });
    }
    
    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();
    
    if (!userData.mfaSecret) {
      return res.status(400).json({ intMessage: "MFA no configurado para este usuario" });
    }
    
    const verified = speakeasy.totp.verify({
      secret: userData.mfaSecret,
      encoding: 'base32',
      token: token,
      window: 1 // Permite 1 código antes/después para sincronización
    });
    
    if (verified) {
      if (!userData.mfaEnabled) {
        await userDoc.ref.update({ mfaEnabled: true });
      }
      res.json({ success: true, intMessage: "MFA verificado correctamente" });
    } else {
      res.status(401).json({ success: false, intMessage: "Código MFA inválido" });
    }
  } catch (error) {
    handleError(res, error, "Error al verificar MFA");
  }
});

// Obtener usuarios
// Obtener usuario por ID
// Obtener todos los usuarios--
app.get("/api/usuarios", verificarToken, async (req, res) => {
  try {
      const usersSnapshot = await db.collection("Users").get();
      const users = usersSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
      res.status(200).json({ intMessage: "Usuarios encontrados", data: users });
  } catch (error) {
      handleError(res, error, "Error al obtener usuarios");
  }
});

// Obtener usuario por ID
app.get("/api/usuarios/:id", verificarToken, async (req, res) => {
  try {
      const userId = req.params.id;
      const userDoc = await getDocumentById("Users", userId);
      res.status(200).json({ intMessage: "Usuario encontrado", data: userDoc });
  } catch (error) {
      if (error.message.includes("no encontrado")) {
          return res.status(404).json({ intMessage: error.message });
      }
      handleError(res, error, "Error al obtener usuario");
  }
});

app.put("/api/users/:id", verificarToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const { email, fullName, username } = req.body;

    // Verificar que el usuario que hace la petición es el mismo que se quiere modificar
    if (req.usuario.id !== userId) {
      return res.status(403).json({ intMessage: "No autorizado para modificar este usuario" });
    }

    // Validar datos
    if (!email || !fullName || !username) {
      return res.status(400).json({ intMessage: "Faltan datos requeridos" });
    }

    // Verificar si el nuevo username ya existe (excepto para el mismo usuario)
    const usernameCheck = await db.collection("Users")
      .where("username", "==", username)
      .where(admin.firestore.FieldPath.documentId(), "!=", userId)
      .get();

    if (!usernameCheck.empty) {
      return res.status(400).json({ intMessage: "El nombre de usuario ya está en uso" });
    }

    // Verificar si el nuevo email ya existe (excepto para el mismo usuario)
    const emailCheck = await db.collection("Users")
      .where("email", "==", email)
      .where(admin.firestore.FieldPath.documentId(), "!=", userId)
      .get();

    if (!emailCheck.empty) {
      return res.status(400).json({ intMessage: "El correo electrónico ya está en uso" });
    }

    // Actualizar datos
    await db.collection("Users").doc(userId).update({
      username: username,
      email: email,
      nombre: fullName,
      updated_at: new Date()
    });

    res.status(200).json({ intMessage: "Perfil actualizado con éxito" });
  } catch (error) {
    handleError(res, error, "Error al actualizar el perfil");
  }
});

// Servir archivos estáticos desde la carpeta "uploads"
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// colecciones registro
app.post("/api/registroColeccionables", upload.array("imagenes", 10), async (req, res) => {
  const { escala, nombre, fechaLimite } = req.body;

  if (!escala || !nombre  || !fechaLimite) {
    return res.status(400).json({ intMessage: "Faltan datos" });
  }

  try {
    

    const coleccionableSnapshot = await db.collection("Coleccionable").where("nombre", "==", nombre).get();
    if (!coleccionableSnapshot.empty) {
      return res.status(400).json({ intMessage: "El coleccionable ya existe" });
    }

    const fechaPublicacion = new Date();
    const newDocRef = await db.collection("Coleccionable").add({
      escala,
      fechaLimite,
      nombre,
      fechaPublicacion,
    });

    const coleccionableId = newDocRef.id;

    // Crear la carpeta final para las imágenes
    const finalPath = path.join(__dirname, "uploads", coleccionableId);
    if (!fs.existsSync(finalPath)) {
      fs.mkdirSync(finalPath, { recursive: true });
    }

    // Mover las imágenes de la carpeta temporal a la carpeta final
    const imagenes = req.files.map((file) => {
      const tempFilePath = file.path;
      const finalFilePath = path.join(finalPath, file.filename);
      fs.renameSync(tempFilePath, finalFilePath);
      return `/uploads/${coleccionableId}/${file.filename}`;
    });

    // Guardar las rutas de las imágenes en la base de datos
    await newDocRef.update({ imagenes });

    res.status(201).json({ intMessage: "Coleccionable registrado con éxito", id: coleccionableId, imagenes });
  } catch (error) {
    handleError(res, error, "Error al registrar coleccionable");
  }
});

// Obtener coleccionables
// Obtener coleccionable por ID
app.get("/api/colecciones", async (req, res) => {
  try {
    const { escala } = req.query; // Cambiar de req.body a req.query
    if (!escala) {
      return res.status(400).json({ intMessage: "Escala no proporcionada" });
    }

    // Obtener los documentos de la colección "Coleccionable" con la escala proporcionada
    const collecSnapshot = await db.collection("Coleccionable").where("escala", "==", escala).get();
    const colecciones = collecSnapshot.docs.map((doc) => {
      const data = doc.data();
      // Asegurarse de que las rutas de las imágenes sean accesibles
      const imagenes = data.imagenes?.map((imagen) => `${req.protocol}://${req.get('host')}${imagen}`) || [];
      return { id: doc.id, ...data, imagenes };
    });

    res.status(200).json({ intMessage: "Coleccionables encontrados", data: colecciones });
  } catch (error) {
    handleError(res, error, "Error al obtener coleccionables");
  }
});

// Ruta para solicitar recuperación
app.post("/api/solicitar-recuperacion", async (req, res) => {
  const { usuario } = req.body;
  
  try {
    const userSnapshot = await db.collection("Users").where("username", "==", usuario).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ intMessage: "Usuario no encontrado" });
    }

    const userData = userSnapshot.docs[0].data();
    const userId = userSnapshot.docs[0].id;
    
    // Generar token de recuperación (válido por 1 hora)
    const recoveryToken = jwt.sign(
      { userId, username: usuario },
      "claveSecretaRecuperacion",
      { expiresIn: "1h" }
    );

    // Guardar token en la base de datos
    await userSnapshot.docs[0].ref.update({ 
      recovery_token: recoveryToken,
      recovery_token_expires: new Date(Date.now() + 3600000) // 1 hora
    });

    // Aquí podrías enviar el correo o SMS con el token
    if (userData.email) {
      const mailOptions = {
        from: 'Carcollection <eramireznieves25@gmail.com>',
        to: userData.email,
        subject: 'Código de recuperación de cuenta',
        text: `Tu código de recuperación es: ${recoveryToken}\n\nEl código expira en 1 hora.`,
        html: `<p>Tu código de recuperación es: <strong>${recoveryToken}</strong></p>
               <p>El código expira en 1 hora.</p>`
      };

      await transporter.sendMail(mailOptions);
    }
    // Por ahora solo lo devolvemos para pruebas
    res.status(200).json({ 
      intMessage: "Se ha enviado un código de recuperación",
      methodsAvailable: {
        email: userData.email ? true : false,
        sms: userData.phone ? true : false,
        questions: userData.securityQuestions ? true : false
      }
    });



  } catch (error) {
    handleError(res, error, "Error al solicitar recuperación");
  }
});

// Ruta para verificar código/token
app.post("/api/verificar-recuperacion", async (req, res) => {
  const { usuario, token } = req.body;
  
  try {
    const userSnapshot = await db.collection("Users").where("username", "==", usuario).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ intMessage: "Usuario no encontrado" });
    }

    const userData = userSnapshot.docs[0].data();
    
    // Verificar token
    if (userData.recovery_token !== token || new Date(userData.recovery_token_expires) < new Date()) {
      return res.status(401).json({ intMessage: "Código inválido o expirado" });
    }

    res.status(200).json({ 
      intMessage: "Código verificado correctamente",
      token: userData.recovery_token
    });

  } catch (error) {
    handleError(res, error, "Error al verificar código");
  }
});

// Ruta para cambiar contraseña
app.post("/api/cambiar-contrasena", async (req, res) => {
  const { token, nuevaContra } = req.body;
  
  try {
    // Verificar token
    const decoded = jwt.verify(token, "claveSecretaRecuperacion");
    
    const userSnapshot = await db.collection("Users").where("username", "==", decoded.username).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ intMessage: "Usuario no encontrado" });
    }

    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();
    
    // Verificar que el token coincida y no esté expirado
    if (userData.recovery_token !== token || new Date(userData.recovery_token_expires) < new Date()) {
      return res.status(401).json({ intMessage: "Token inválido o expirado" });
    }

    // Cambiar contraseña
    const hashPassword = await bcrypt.hash(nuevaContra, 10);
    await userDoc.ref.update({ 
      password: hashPassword,
      recovery_token: null,
      recovery_token_expires: null
    });

    res.status(200).json({ intMessage: "Contraseña cambiada con éxito" });

  } catch (error) {
    handleError(res, error, "Error al cambiar contraseña");
  }
});
//pujas
// Ruta para obtener última puja
app.get('/api/bids/:itemId/latest', async (req, res) => {
  try {
    const itemId = req.params.itemId;
    const snapshot = await db.collection('Bids')
      .where('itemId', '==', itemId)
      .orderBy('timestamp', 'desc')
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(404).json({ intMessage: 'No hay pujas registradas' });
    }

    const bidData = snapshot.docs[0].data();
    res.status(200).json({
      id: snapshot.docs[0].id,
      ...bidData,
      timestamp: bidData.timestamp.toDate()
    });
  } catch (error) {
    handleError(res, error, "Error al obtener última puja");
  }
});

// Ruta para crear nueva puja (protegida)
app.post('/api/bids', verificarToken, async (req, res) => {
  try {
    const { itemId, amount } = req.body;
    const userId = req.usuario.id;

    if (!itemId || !amount) {
      return res.status(400).json({ intMessage: "Faltan datos requeridos" });
    }

    const bidAmount = parseFloat(amount);
    if (isNaN(bidAmount)) {
      return res.status(400).json({ intMessage: "Monto inválido" });
    }

    // Verificar última puja
    const latestBidSnapshot = await db.collection('Bids')
      .where('itemId', '==', itemId)
      .orderBy('timestamp', 'desc')
      .limit(1)
      .get();

    if (!latestBidSnapshot.empty) {
      const lastBid = latestBidSnapshot.docs[0].data();
      if (bidAmount <= lastBid.amount) {
        return res.status(400).json({ 
          intMessage: `La puja debe ser mayor a $${lastBid.amount}`
        });
      }
    }

    // Crear nueva puja
    const newBid = {
      itemId,
      userId,
      amount: bidAmount,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('Bids').add(newBid);
    
    // Obtener datos del usuario
    const userDoc = await db.collection('Users').doc(userId).get();
    const userData = userDoc.data();

    res.status(201).json({
      id: docRef.id,
      ...newBid,
      timestamp: new Date(),
      userName: userData.username
    });
  } catch (error) {
    handleError(res, error, "Error al registrar puja");
  }
});

// Ruta para obtener todas las pujas de un artículo
app.get('/api/bids/:itemId', async (req, res) => {
  try {
    const itemId = req.params.itemId;
    const snapshot = await db.collection('Bids')
      .where('itemId', '==', itemId)
      .orderBy('timestamp', 'desc')
      .get();

    const bids = await Promise.all(snapshot.docs.map(async doc => {
      const bidData = doc.data();
      const userDoc = await db.collection('Users').doc(bidData.userId).get();
      return {
        id: doc.id,
        ...bidData,
        timestamp: bidData.timestamp.toDate(),
        userName: userDoc.data().username
      };
    }));

    res.status(200).json(bids);
  } catch (error) {
    handleError(res, error, "Error al obtener pujas");
  }
});

//convercion de moneta
const currencyWSS = new WebSocket.Server({ port: 3003 });

currencyWSS.on('connection', (ws) => {
    console.log('Client connected to currency websocket');
    
    // Función para obtener y enviar tasas de cambio
    const fetchAndSendRates = async (baseCurrency = 'USD') => {
        try {
            const response = await axios.get(`https://api.frankfurter.app/latest?from=${baseCurrency}`);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'exchange_rates',
                    data: response.data.rates,
                    base: baseCurrency,
                    date: response.data.date
                }));
            }
        } catch (error) {
            console.error('Error fetching exchange rates:', error);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'error',
                    message: 'Failed to fetch exchange rates'
                }));
            }
        }
    };

    // Enviar tasas iniciales
    fetchAndSendRates();

    // Configurar intervalo para actualizaciones periódicas
    const intervalId = setInterval(() => fetchAndSendRates(), 30000); // Actualizar cada 30 segundos

    // Manejar mensajes del cliente (por ejemplo, cambiar moneda base)
    ws.on('message', (message) => {
        const msg = JSON.parse(message);
        if (msg.type === 'change_base') {
            fetchAndSendRates(msg.currency);
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected from currency websocket');
        clearInterval(intervalId);
    });
});



const PORT = 3001;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
