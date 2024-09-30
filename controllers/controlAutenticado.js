import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";
import crypto from "crypto";
import argon2 from "argon2";
import UserModel from "../bdesquemas/userModel.js";
import speakeasy from "speakeasy";
import { v4 as uuidv4 } from "uuid";

//Funcion de login con validacion de token
async function login(req, res) {
  console.log(req.body);
  const user = req.body.nom_usu;
  const password = req.body.contr_usu;

  // Validación por si se envía vacío
  if (!user || !password) {
    return res.status(400).json({ error: "Usuario o contraseña inválidos" });
  }

  try {
    // Buscar el usuario en la base de datos usando Mongoose
    const usuarioArevisar = await UserModel.findOne({ nombre: user });

    // Si no existe el usuario
    if (!usuarioArevisar) {
      return res.status(400).json({
        status: "Error",
        message: "No existe",
      });
    }

    // Comparación de la contraseña
    const loginCorrecto = await bcryptjs.compare(
      password,
      usuarioArevisar.contraseña
    );
    if (!loginCorrecto) {
      return res.status(400).json({
        status: "Error",
        message: "Error - Usuario o contraseña inválidos",
      });
    }

    // Token de autorización de login
    const token = jsonwebtoken.sign(
      { user: usuarioArevisar.nom_usu },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRATION,
      }
    );

    // Opciones de Cookie
    const cookieOption = {
      expires: new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRES * 60 * 60 * 1000
      ),
      path: "/",
      sameSite: "Lax", // Para permitir que las cookies se compartan en diferentes sitios
      //secure: true, // Para requerir conexiones seguras (HTTPS)
    };

    console.log("Token generado:", token); // Agrega esto para verificar el contenido del token
    // Enviar cookie y respuesta
    res.cookie("jwt", token, cookieOption);
    res.send({
      status: "ok",
      message: "Usuario Logeado",
      redirect: "/dashboard",
      user: usuarioArevisar,
    });
  } catch (error) {
    console.error("Error al obtener usuarios de la base de datos:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
}

// Función para generar la clave privada a partir del secreto usando Argon2id
async function generarClavePrivadaDesdeSecreto(secreto) {
  const saltClavePrivada = crypto.randomBytes(16); // Generar un salt para derivar la clave privada

  // Derivar una clave privada de 32 bytes usando Argon2id
  const clavePrivadaDerivada = await argon2.hash(secreto, {
    type: argon2.argon2id,
    salt: saltClavePrivada,
    hashLength: 32, // Longitud de la clave privada en bytes
    timeCost: 3, // Número de iteraciones
    memoryCost: 2 ** 16, // Memoria utilizada en KB -> 64 MB
    parallelism: 1, // Número de hilos
    raw: true, // Para obtener la clave derivada en formato de buffer
  });
  console.log("Clave secreta: ", clavePrivadaDerivada.toString("hex"));
  return {
    clavePrivadaDerivada: clavePrivadaDerivada.toString("hex"),
    saltClavePrivada,
  };
}

// Función para cifrar la clave privada con la contraseña usando Argon2id
async function cifrarClavePrivada(clavePrivada, contraseña) {
  const salt = crypto.randomBytes(16); // Generar un salt aleatorio de 16 bytes

  // Derivar una clave simétrica de 256 bits usando Argon2id
  const claveSimetrica = await argon2.hash(contraseña, {
    type: argon2.argon2id,
    salt: salt,
    hashLength: 32, // Longitud de clave simétrica (256 bits)
    timeCost: 3,
    memoryCost: 2 ** 16, // 64 MB
    parallelism: 1,
    raw: true, // Para obtener la clave en formato de buffer
  });

  const iv = crypto.randomBytes(16); // Generar un vector de inicialización (IV) de 16 bytes
  const cipher = crypto.createCipheriv("aes-256-cbc", claveSimetrica, iv);

  let clavePrivadaCifrada = cipher.update(clavePrivada, "utf8", "hex");
  clavePrivadaCifrada += cipher.final("hex");

  return {
    clavePrivadaCifrada,
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
  };
}

async function register(req, res) {
  console.log(req.body);
  const user = req.body.nom_usu;
  const password = req.body.contr_usu;
  const secreto = req.body.secreto;

  // Validación por si se envía vacío
  if (!user || !password || !secreto) {
    return res
      .status(400)
      .json({ error: "Usuario, contraseña o secreto inválidos" });
  }

  try {
    // Verificación si el usuario ya existe
    const usuarioArevisar = await UserModel.findOne({ nombre: user });
    if (usuarioArevisar) {
      return res
        .status(400)
        .json({ status: "Error", message: "Este usuario ya existe" });
    }

    // Generar el salt y hash de la contraseña
    const saltRounds = 10;
    const salt = await bcryptjs.genSalt(saltRounds);
    const hashPassword = await bcryptjs.hash(password, salt);

    // Paso 1: Generar la clave privada derivada a partir del secreto
    const { clavePrivadaDerivada, saltClavePrivada } =
      await generarClavePrivadaDesdeSecreto(secreto);

    // Paso 2: Cifrar la clave privada usando la contraseña del usuario
    const {
      clavePrivadaCifrada,
      salt: saltCifrado,
      iv,
    } = await cifrarClavePrivada(clavePrivadaDerivada, password);

    // Generar un secreto para el 2FA usando Speakeasy
    const secret2FA = speakeasy.generateSecret({ length: 20 });

    // Crear el nuevo usuario con Mongoose
    const nuevoUsuario = new UserModel({
      userID: uuidv4(), // Generar un ID único
      nombre: user,
      contraseña: hashPassword,
      clavePrivadaCifrada, // Guardar la clave privada cifrada
      saltClavePrivada: saltClavePrivada.toString("hex"), // Salt usado para derivar la clave privada
      saltCifrado: saltCifrado.toString("hex"), // Salt usada para derivar la clave simétrica
      iv: iv.toString("hex"), // IV usado para el cifrado AES
      secret2FA: secret2FA.base32, // Almacenar el secreto del 2FA (en base32 para su uso posterior)
    });

    // Guardar el nuevo usuario en la base de datos
    await nuevoUsuario.save();

    return res.status(201).json({
      status: "ok",
      message:
        "Usuario: " + nuevoUsuario.nombre + " registrado en la base de datos",
      redirect: "/login",
      secret2FA: {
        otpauth_url: secret2FA.otpauth_url,
        base32: secret2FA.base32,
      }, // Enviar la URL para el QR (otpauth URL)
      userID: nuevoUsuario.userID,
    });
  } catch (error) {
    console.error("Error al registrar el usuario:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
}

const methods = {
  register,
  login,
};

export default methods;
