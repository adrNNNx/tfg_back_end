import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import morgan from "morgan";
import multer from 'multer';
import cookieParser from "cookie-parser";
import middlewares from "./middleware/authorization.js";
import methods from "./controllers/controlAutenticado.js";
import cors from "cors";
import UserModel from './bdesquemas/userModel.js';
import recepcionDatos from "./controllers/recepcionDatos.js";

const upload = multer(); // Almacena archivos en memoria

const app = express();
dotenv.config();

const PORT = process.env.PORT || 7000;
const MONGOURL = process.env.MONGO_URL;

mongoose.connect(MONGOURL).then(() => {
    console.log("Base de datos conectada de forma correcta");
    app.listen(PORT, () => {
      console.log("Server corriendo en el puerto:", PORT);
    });
  }).catch((error) => {
    console.log("Error conectando a la base de datos:", error);
  });

//Middlewares
app.use(
  cors({
    origin: [
      "http://localhost:3000",
    ],
    credentials: true, // Agregar si es necesario
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE", // Métodos permitidos
    optionsSuccessStatus: 204, // Código de éxito para solicitudes OPTIONS
  })
);
app.use(morgan("dev"));
//Configuracion
app.use(express.json());
app.use(cookieParser());

//Apis de Autorizacion
app.post("/api/register", middlewares.soloAdmin, methods.register);
app.post("/api/login", methods.login);
app.post("/api/verify2fa", methods.verify2FA);
app.get('/api/auth-cookie', async (req, res) => {
  const isCookieValid = await middlewares.revisarCookie(req);
  res.json({ isAuthenticated: isCookieValid });
});

//Api de los documentos
app.post('/api/documentos-credenciales', upload.single('file'), recepcionDatos.credenciales_documentos_hash);
app.post('/api/verificar-firma', upload.single('file'), recepcionDatos.verificarFirmaDocumento);



app.get("/usuarios", async (req, res) => {
  try {
    const userData = await UserModel.find();
    res.json(userData);
  } catch (error) {
    console.error("Error al obtener los usuarios:", error);
    res.status(500).json({ message: "Error al obtener los usuarios" });
  }
});
