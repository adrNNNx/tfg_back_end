import crypto from "crypto";
import bcryptjs from "bcryptjs";
import speakeasy from "speakeasy";
import argon2 from "argon2";
import UserModel from "../bdesquemas/userModel.js";

const hashArchivo = async (buffer) => {
  return crypto.createHash("sha256").update(buffer).digest("hex"); // Cambia 'sha256' si necesitas otro algoritmo
};

async function descifrarClavePrivada(
  clavePrivadaCifrada,
  contraseña,
  saltCifradoHex,
  ivHex
) {
  // Convertir salt y IV de hexadecimal a buffer
  const salt = Buffer.from(saltCifradoHex, "hex");
  const iv = Buffer.from(ivHex, "hex");

  // Derivar la misma clave simétrica usada para el cifrado
  const claveSimetrica = await argon2.hash(contraseña, {
    type: argon2.argon2id,
    salt: salt,
    hashLength: 32, // Longitud de clave simétrica (256 bits)
    timeCost: 3,
    memoryCost: 2 ** 16, // 64 MB
    parallelism: 1,
    raw: true, // Para obtener la clave en formato de buffer
  });

  // Crear el descifrador usando AES-256-CBC
  const decipher = crypto.createDecipheriv("aes-256-cbc", claveSimetrica, iv);

  // Descifrar la clave privada
  let clavePrivadaDescifrada = decipher.update(
    clavePrivadaCifrada,
    "hex",
    "utf8"
  );
  clavePrivadaDescifrada += decipher.final("utf8");
  return clavePrivadaDescifrada;
}

async function credenciales_documentos_hash(req, res) {
  // Endpoint para recibir el archivo y los datos del formulario
  try {
    const { privateKey, password, token2FA, userID } = req.body;

    // Validación del documento
    if (!req.file) {
      return res.status(400).send("No se ha subido ningún archivo.");
    }

    // Buscar el usuario en la base de datos para la contraseña
    const user = await UserModel.findOne({ userID });
    if (!user) {
      return res
        .status(404)
        .json({ status: "Error", message: "Usuario no encontrado" });
    }

    // Verificar la contraseña
    const contraseñaCorrecta = await bcryptjs.compare(
      password,
      user.contraseña
    );
    if (!contraseñaCorrecta) {
      return res.status(400).json({
        status: "Error",
        message: "Error - credenciales ingresadas inválidas",
      });
    }

    // Verificar el token 2FA
    const verified = speakeasy.totp.verify({
      secret: user.secret2FA,
      encoding: "base32",
      token: token2FA,
    });

    if (!verified) {
      return res.status(400).json({
        status: "Error",
        message: "Error - credenciales ingresadas inválidas",
      });
    }

    // Lógica para hash del archivo
    const hash = await hashArchivo(req.file.buffer); // Usa req.file.buffer para acceder al contenido del archivo

    //Clave privada descifrada
    const clavePrivadaDescifrada = await descifrarClavePrivada(
      user.clavePrivadaCifrada,
      password,
      user.saltCifrado,
      user.iv
    );

    // Aquí podrías enviar el hash a tu contrato inteligente
    console.log("Hash del archivo:", hash);
    console.log("Datos recibidos:", { privateKey, password, token2FA, userID });
    console.log("Clave privada descifrada:", clavePrivadaDescifrada);

    // Respuesta al cliente
    res.status(200).send({
      message: "Archivo y datos verificados y recibidos exitosamente.",
      hash,
    });
  } catch (error) {
    console.error("Error al procesar el archivo:", error);
    res.status(500).send("Error interno del servidor");
  }
}

const recepcionDatos = {
  credenciales_documentos_hash,
};

export default recepcionDatos;
