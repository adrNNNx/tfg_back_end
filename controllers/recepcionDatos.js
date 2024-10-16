import crypto from "crypto";
import bcryptjs from "bcryptjs";
import speakeasy from "speakeasy";
import argon2 from "argon2";
import UserModel from "../bdesquemas/userModel.js";
import DocumentModel from "../bdesquemas/signedDocuments.js";
import { v4 as uuidv4 } from "uuid";

//Curva eliptica de ethereum
import pkg from "elliptic";
const { ec: EC } = pkg;
const ec = new EC("secp256k1"); // Ethereum utiliza la curva secp256k1

//Web3 para conectar con el contrato
import Web3 from "web3";
import contractABI from "../../contrato_inteligente/abis/ContratoFirma.json" assert { type: "json" }; // ABI del contrato compilado

const contractAddress = "0x3005F3719B6D385c4D6892D4503c1EC85194E3Fe"; // Dirección del contrato en la blockchain
const accountAddress = "0xC3b4181fb3823d09d672478d7E2184d9d7A292a0"; //Direccion de la cuenta de ganache en la blockchain
const clavePrivadaGanache =
  "0x5d15cb6a869a27d6f4a1ebb3aa7b6efca050f3331519805410d369baea211ecd";

// Conexión a la red de ganache
const web3 = new Web3("http://127.0.0.1:7545"); // O la URL de Ethereum
// Instancia del contrato
const contratoFirmas = new web3.eth.Contract(contractABI.abi, contractAddress);

//Se firma el documento
async function firmarDocumento(hashDocumento, clavePrivada, clavePublica) {
  // Formateo de la clave privada, publica para poder firmar
  /*  clavePrivada = "0x" + clavePrivada;*/
  const address = "0x" + web3.utils.keccak256(clavePublica.slice(2)).slice(26);

  //Necesitamos quitar el 0x al inicio del hash antes de firmar si no nos dara error a la hora de verificar la firma
  //Para eso está parte de la función así se guarda la firma sin el prefijo
  const hashDocumentoFirmar = hashDocumento.startsWith("0x")
    ? hashDocumento.slice(2)
    : hashDocumento;
  // Generar el par de claves usando la clave privada
  const keyPair = ec.keyFromPrivate(clavePrivada);

  // Obtener la clave pública en formato hexadecimal
  const clavePublicaGen = keyPair.getPublic("hex");
  console.log(`Clave pública generada: ${clavePublicaGen}`);

  // Firmar el hash del documento con la clave privada
  const firma = keyPair.sign(hashDocumentoFirmar);

  const signature = {
    r: "0x" + firma.r.toString("hex"),
    s: "0x" + firma.s.toString("hex"),
    v: firma.recoveryParam + 27, // Si necesitas el v como 27 o 28 para compatibilidad ECDSA
  };

  // Asignar valores r, s y v
  const { r, s, v } = signature;

  console.log("hash del documento original: ",hashDocumento);
  console.log("hash del documento sin prefijo firmado: ",hashDocumentoFirmar);
  console.log("Firma: ", signature);
  console.log("r original: ", firma.r.toString("hex"));
  console.log("r: ", r);
  console.log("s: ", s);
  console.log("s original: ", firma.s.toString("hex"));

  // Firmar el hash del documento usando la clave privada
  /*   const firma = web3.eth.accounts.sign(hashDocumento, clavePrivada);
  console.log("Firma actual: ", firma);
  // Extraer los valores v, r y s de la firma
  const { v, r, s } = firma; */

  // Llamar a la función del contrato para almacenar la firma
  const tx = contratoFirmas.methods.almacenarFirmaDocumento(
    hashDocumento,
    address,
    v,
    r,
    s
  );

  // Opciones de transacción
  const gas = await tx.estimateGas({ from: accountAddress }); // Direccion de la cuenta que administra el contrato
  const gasPrice = await web3.eth.getGasPrice();

  // Crear la transacción firmada
  const data = tx.encodeABI();
  const nonce = await web3.eth.getTransactionCount(accountAddress, "latest");

  const signedTx = await web3.eth.accounts.signTransaction(
    {
      to: contractAddress,
      data,
      gas,
      gasPrice,
      nonce,
    },
    clavePrivadaGanache
  );

  // Enviar la transacción
  const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);

  //Hash de la transaccion para identificar el bloque luego
  const transactionHash = receipt.transactionHash;

  return { receipt, transactionHash };
}

// Función para hashear el archivo y devolver el hash en formato bytes32 con el prefijo '0x'
const hashearArchivo = async (buffer) => {
  // Generar el hash con sha256
  const hash = crypto.createHash("sha256").update(buffer).digest("hex");
  return "0x" + hash;
};

//Se descifra la clave privada del usuario
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

// Función para obtener los eventos de firma del documento desde la blockchain
async function obtenerFirmasDeDocumento(hashDocumento) {
  try {
    // Filtrar los eventos de firma usando el hash del documento
    const eventosFirmas = await contratoFirmas.getPastEvents(
      "FirmaDocumentoRegistrada",
      {
        filter: { hash: hashDocumento }, // Filtrar por el hash del documento
        fromBlock: 0, // O desde un bloque específico
        toBlock: "latest",
      }
    );

    // Procesar los eventos y extraer las firmas
    const firmas = eventosFirmas.map((evento) => ({
      firmante: evento.returnValues.firmante,
      v: evento.returnValues.v,
      r: evento.returnValues.r,
      s: evento.returnValues.s,
      timestamp: evento.returnValues.timestamp,
    }));

    return {
      status: "Success",
      message: "Firmas recuperadas con éxito.",
      firmas,
    };
  } catch (error) {
    console.error("Error al recuperar las firmas:", error);
    return {
      status: "Error",
      message: "Ocurrió un error al recuperar las firmas.",
    };
  }
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

    // Obtenemos las firmas almacenadas en la blockchain
    const firmaUsuario = await obtenerFirmasDeDocumento(hashDocumento);
    console.log("Firmas recuperadas de la blockchain: ", firmaUsuario);

    // Recuperamos los datos de la firma del blockchain
    const { v, r, s } = firmaUsuario.firmas[0];

    // 1. Convertimos los valores de `r` y `s` a su formato hexadecimal
    const rHex = r.slice(2); // Quita '0x'
    const sHex = s.slice(2); // Quita '0x'

    // Creamos el objeto de la firma
    const firma = { r: rHex, s: sHex }; // Cambiar a r y s

    // Verificamos si la clave pública comienza con '04' (formato no comprimido)
    let clavePublica = user.clavePublica;
    if (clavePublica.startsWith("04")) {
      // Decodificamos la clave pública en un punto de la curva
      clavePublica = ec.keyFromPublic(clavePublica, "hex").getPublic();
    }

    // 2. Utilizamos el hash del documento para verificar la valides de la firma
    const mensajeHash = hashDocumento.startsWith("0x")
      ? hashDocumento.slice(2)
      : hashDocumento;

    // 3. Verificamos la firma usando la clave pública del usuario y el hash del documento
    const firmaValida = ec.verify(mensajeHash, firma, clavePublica);

    if (!firmaValida) {
      return res.status(400).json({
        status: "Error",
        message: "La firma del documento no es válida.",
      });
    }

    // Si la firma es válida, enviamos los datos del documento al frontend
    return res.status(200).json({
      status: "OK",
      message: "Este documento ya ha sido firmado y la firma es válida.",
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

//Está funcion se encarga de almacenar los documentos en la blockchain
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
    const receipt = await firmarDocumento(
      hashDocumento,
      clavePrivadaDescifrada,
      user.clavePublica
    );

    // Validar si se obtuvo el recibo y contiene transactionHash
    if (!receipt || !receipt.transactionHash) {
      throw new Error(
        "No se pudo obtener el transactionHash de la transacción."
      );
    }

    // Obtener el nombre del documento
    const nombreDocumento = req.file.originalname;

    // Generar la fecha de la firma
    const fechaFirma = new Date().toISOString();

    // Asignar un ID al documento
    const documentID = uuidv4();

    // Hash de la transacción
    const blockchainTxHash = receipt.transactionHash;

    //Nombre del usuario que realizo la firma
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

    // Respuesta al cliente
    res.status(200).send({
      message: "Documento firmado de forma exitosa!.",
      nuevoDocumento,
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
