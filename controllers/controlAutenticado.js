import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";
import crypto from "crypto";
import argon2 from "argon2";
import UserModel from "../bdesquemas/userModel.js";
import speakeasy from "speakeasy";
import Web3 from "web3";
const web3 = new Web3("http://127.0.0.1:7545"); // O la URL de Ethereum
import { v4 as uuidv4 } from "uuid";
import pkg from "elliptic";
const { ec: EC } = pkg;

const ec = new EC("secp256k1"); // Ethereum utiliza la curva secp256k1

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

function obtenerDireccionDesdeClavePublica(clavePublica) {
  // Calcular la dirección Ethereum a partir de la clave pública
  const direccion = web3.utils.keccak256(clavePublica.slice(2)).slice(-40); // Hash de la clave pública
  return `0x${direccion}`; // Retornar la dirección en formato 0x
}

// Función para generar la clave privada a partir del secreto usando Argon2id
async function generarClavePrivadaDesdeSecreto(secreto) {
  let clavePrivadaHex;
  let saltClavePrivada;
  let isValid = false;

  // Este ciclo while lo que hace es en el caso de que se obtenga un numero que no sea valido para el algoritmo de firmado de ethereum.
  while (!isValid) {
    // Generar un salt aleatorio
    saltClavePrivada = crypto.randomBytes(16);

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

    // Convertir a hexadecimal
    clavePrivadaHex = clavePrivadaDerivada.toString("hex");
    console.log("clave privada generada: ", clavePrivadaHex);

    // Validar la clave privada
    try {
      const clavePrivadaBN = ec.keyFromPrivate(clavePrivadaHex, "hex");
      isValid =
        clavePrivadaBN.getPrivate().lt(ec.curve.n) &&
        clavePrivadaBN.getPrivate().gt(0);

      if (!isValid) {
        console.log("Clave privada no válida, generando una nueva...");
      }
    } catch (error) {
      console.log("Error al validar la clave privada:", error);
      isValid = false;
    }
  }

  // La clave privada es válida
  console.log("Clave privada válida");

  return {
    clavePrivadaDerivada: clavePrivadaHex,
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

async function generarClavePublica(clavePrivadaHex) {
  // Convertir la clave privada derivada a un buffer
  const clavePrivadaBuffer = Buffer.from(clavePrivadaHex, "hex");

  // Generar la clave pública usando la curva secp256k1
  const clave = ec.keyFromPrivate(clavePrivadaBuffer);
  const clavePublica = clave.getPublic("hex"); // Obtener la clave pública en formato hexadecimal

  // Obtener la dirección de ethereum desde la clave pública
  const direccion = obtenerDireccionDesdeClavePublica(clavePublica);
  console.log("Dirección Ethereum: ", direccion);

  return clavePublica;
}

async function register(req, res) {
  console.log(req.body);
  const user = req.body.nom_usu;
  const nombreReal = req.body.nombreReal;
  const apellido = req.body.apellido;
  const password = req.body.contr_usu;
  const secreto = req.body.secreto;

  if (!user || !password || !secreto) {
    return res
      .status(400)
      .json({ error: "Usuario, contraseña o secreto inválidos" });
  }

  try {
    const usuarioArevisar = await UserModel.findOne({ nombre: user });
    if (usuarioArevisar) {
      return res
        .status(400)
        .json({ status: "Error", message: "Este nombre de usuario ya existe" });
    }

    // Generar el hash de la contraseña
    const saltRounds = 10;
    const salt = await bcryptjs.genSalt(saltRounds);
    const hashPassword = await bcryptjs.hash(password, salt);

    // Generar clave privada y pública
    const { clavePrivadaDerivada, saltClavePrivada } =
      await generarClavePrivadaDesdeSecreto(secreto);
    const clavePublica = await generarClavePublica(clavePrivadaDerivada);

    // Cifrar clave privada
    const {
      clavePrivadaCifrada,
      salt: saltCifrado,
      iv,
    } = await cifrarClavePrivada(clavePrivadaDerivada, password);

    // Generar un secreto para el 2FA usando Speakeasy
    const secret2FA = speakeasy.generateSecret({ length: 20 });

    // Enviar el secreto 2FA al frontend, no se guarda el usuario aún
    return res.status(201).json({
      status: "ok",
      secret2FA: {
        otpauth_url: secret2FA.otpauth_url,
        base32: secret2FA.base32,
      },
      userTempData: {
        user,
        nombreReal,
        apellido,
        hashPassword,
        clavePrivadaCifrada,
        clavePublica,
        saltClavePrivada: saltClavePrivada.toString("hex"),
        saltCifrado: saltCifrado.toString("hex"),
        iv: iv.toString("hex"),
        secret2FA: secret2FA.base32,
      },
    });
  } catch (error) {
    console.error("Error al generar 2FA:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
}

async function verify2FA(req, res) {
  const { userTempData, token } = req.body;

  const verified = speakeasy.totp.verify({
    secret: userTempData.secret2FA,
    encoding: "base32",
    token,
  });

  if (verified) {
    try {
      // Guardar al usuario en la base de datos una vez se verifico el token
      const nuevoUsuario = new UserModel({
        userID: uuidv4(),
        nombre: userTempData.user,
        contraseña: userTempData.hashPassword,
        nombreReal: userTempData.nombreReal,
        apellido: userTempData.apellido,
        clavePrivadaCifrada: userTempData.clavePrivadaCifrada,
        clavePublica: userTempData.clavePublica,
        saltClavePrivada: userTempData.saltClavePrivada,
        saltCifrado: userTempData.saltCifrado,
        iv: userTempData.iv,
        secret2FA: userTempData.secret2FA,
      });

      await nuevoUsuario.save();
      return res.status(200).json({
        status: "ok",
        message: "Código 2FA verificado correctamente",
        redirect: "/login",
      });
    } catch (error) {
      console.error("Error al registrar el usuario:", error);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
  } else {
    return res
      .status(400)
      .json({ status: "error", message: "Token de 2FA inválido" });
  }
}

const methods = {
  register,
  login,
  verify2FA,
};

export default methods;
