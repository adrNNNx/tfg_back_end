import crypto from "crypto";
import bcryptjs from "bcryptjs";
import speakeasy from "speakeasy";
import argon2 from "argon2";
import UserModel from "../bdesquemas/userModel.js";
import DocumentModel from "../bdesquemas/signedDocuments.js";
import { v4 as uuidv4 } from "uuid";
import pkg from "elliptic";
const { ec: EC } = pkg;
const ec = new EC("secp256k1"); // Ethereum utiliza la curva secp256k1

const hashearArchivo = async (buffer) => {
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

async function firmarMensaje(clavePrivadaHex, hashDocumento) {
  // Convertir clave privada a formato adecuado
  const clavePrivada = ec.keyFromPrivate(clavePrivadaHex, "hex");

  // Firmar el hash del documento
  const firma = clavePrivada.sign(hashDocumento);

  // Convertir la firma a un formato que pueda ser compartido (r y s en hexadecimal)
  const firmaHex = {
    r: firma.r.toString("hex"),
    s: firma.s.toString("hex"),
    recoveryParam: firma.recoveryParam, // Parámetro para recuperación
  };

  console.log("Firma:", firmaHex);
  return firmaHex;
}

// Función para verificar la firma con el hash del archivo
async function verificarFirmaDocumento(req, res) {
  try {
    // Validación del archivo cargado
    if (!req.file) {
      return res.status(400).send("No se ha subido ningún archivo.");
    }

    // Obtenemos el hash del documento para comparar con el de la base de datos
    const hashDocumento = await hashearArchivo(req.file.buffer); // Usa req.file.buffer para acceder al contenido del archivo

    // Buscamos en la base de datos el documento que tenga el mismo hash
    const documentoExistente = await DocumentModel.findOne({ hashDocumento });

    // Si no existe ningún documento con ese hash, indicamos que no se ha firmado
    if (!documentoExistente) {
      return res.status(404).json({
        status: "Error",
        message: "El documento ingresado no ha sido firmado aún.",
      });
    }

    const userID = documentoExistente.userID;
    const user = await UserModel.findOne({ userID });

    // Si el documento existe, devolvemos la información del documento firmado
    return res.status(200).json({
      status: "OK",
      message: "Este documento ya ha sido firmado.",
      datosDocumento: {
        userID: documentoExistente.userID,
        firmante: user.nombre,
        hashDocumento: hashDocumento,
        clavePublica: user.clavePublica,
        documentID: documentoExistente.documentID,
        nombreDocumento: documentoExistente.nombreDocumento,
        fechaFirma: documentoExistente.fechaFirma,
        blockchainTxHash: documentoExistente.blockchainTxHash,
      },
    });
  } catch (error) {
    console.error("Error al verificar el documento:", error);
    res.status(500).json({
      status: "Error",
      message: "Error interno del servidor",
    });
  }
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

    // Obtenemos el hash del documento
    const hashDocumento = await hashearArchivo(req.file.buffer); // Usa req.file.buffer para acceder al contenido del archivo

    // Buscar si el hash del documento ya está en la base de datos, para no firmar 2 veces
    const documentoExistente = await DocumentModel.findOne({
      hashDocumento,
    });
    //Si existe entonces devolvemos un error
    if (documentoExistente) {
      return res.status(400).json({
        status: "Error",
        message:
          "Error - El documento ya ha sido firmado y no se puede volver a firmar.",
      });
    }

    //Clave privada descifrada
    const clavePrivadaDescifrada = await descifrarClavePrivada(
      user.clavePrivadaCifrada,
      password,
      user.saltCifrado,
      user.iv
    );
    // Firma de documento con el contrato inteligente
    const firma = await firmarMensaje(clavePrivadaDescifrada, hashDocumento);
    const firmaLegible = `r: ${firma.r}, s: ${firma.s}`;

    // Obtener el nombre del documento
    const nombreDocumento = req.file.originalname;

    // Generar la fecha de la firma
    const fechaFirma = new Date().toISOString();

    // Asignar un ID al documento
    const documentID = uuidv4();

    //Dato estatico para la transaccion de la blockchain
    const blockchainTxHash = "0x123456789abcdef";
    const nombreUsuario = user.nombre;

    const nuevoDocumento = new DocumentModel({
      documentID,
      userID,
      nombreDocumento,
      fechaFirma,
      hashDocumento,
      blockchainTxHash,
    });

    // Guardar el nuevo documento en la base de datos
    await nuevoDocumento.save();

    // Aquí podrías enviar el hash a tu contrato inteligente
    console.log("Hash del archivo:", hashDocumento);
    console.log("Datos recibidos:", { privateKey, password, token2FA, userID });
    console.log("Clave privada descifrada:", clavePrivadaDescifrada);

    // Respuesta al cliente
    res.status(200).send({
      message: "Documento firmado de forma exitosa!.",
      nuevoDocumento,
      firmaLegible,
      nombreUsuario,
    });
  } catch (error) {
    console.error("Error al procesar el archivo:", error);
    res.status(500).send("Error interno del servidor");
  }
}

const recepcionDatos = {
  credenciales_documentos_hash,
  verificarFirmaDocumento,
};

export default recepcionDatos;
