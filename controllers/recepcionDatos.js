import crypto from "crypto";
import bcryptjs from "bcryptjs";
import speakeasy from "speakeasy";
import dotenv from "dotenv";
import argon2 from "argon2";
import UserModel from "../bdesquemas/userModel.js";
import DocumentModel from "../bdesquemas/signedDocuments.js";
import VerificationModel from "../bdesquemas/verificationLogModel.js";

dotenv.config();

//Curva eliptica de ethereum
import pkg from "elliptic";
const { ec: EC } = pkg;
const ec = new EC("secp256k1"); // Ethereum utiliza la curva secp256k1

//Web3 para conectar con el contrato
import Web3 from "web3";
//import contractABI from "../../contrato_inteligente/abis/ContratoFirma.json" assert { type: "json" }; // ABI del contrato compilado
const contractABI = await import(
  "../blockchain/abis/FirmaContrato.json",
  {
    assert: { type: "json" },
  }
).then((module) => module.default);

const contractAddress = process.env.CONTRACT_ADDRESS; // Dirección del contrato en la blockchain
const accountAddress = process.env.ACCOUNT_ADDRESS; //Direccion de la cuenta de ganache en la blockchain
const clavePrivadaMetaMask = process.env.PRIVATE_KEY_ACCOUNT;

// Conexión a la red a través de Infura
const infuraUrl = `https://mainnet.infura.io/v3/${process.env.INFURA_PROJECT_ID}`;
const web3 = new Web3(new Web3.providers.HttpProvider(infuraUrl));

// Instancia del contrato en la red de Infura
const contratoFirmas = new web3.eth.Contract(contractABI.abi, contractAddress);

//Se firma el documento
async function firmarDocumento(hashDocumento, clavePrivada, clavePublica) {
  //Utilizamos esto para almacenar la clave publica en su formato comprimido
  const address = "0x" + web3.utils.keccak256(clavePublica.slice(2)).slice(26);

  //Necesitamos quitar el 0x al inicio del hash antes de firmar si no nos dara error a la hora de verificar la firma
  //Para eso está parte de la función así se guarda la firma sin el prefijo
  const hashDocumentoFirmar = hashDocumento.startsWith("0x")
    ? hashDocumento.slice(2)
    : hashDocumento;

  // Generar el par de claves usando la clave privada
  const keyPair = ec.keyFromPrivate(clavePrivada);

  // Obtener la clave pública en formato hexadecimal
  let clavePublicaGen = ec.keyFromPublic(clavePublica, "hex").getPublic();

  // Firmar el hash del documento con la clave privada
  const firma = keyPair.sign(hashDocumentoFirmar);

  // Convertir r y s a cadenas hexadecimales
  let rHex = firma.r.toString("hex");
  let sHex = firma.s.toString("hex");

  // Asegurarse de que r y s tengan 64 caracteres (32 bytes en hexadecimal)
  // Si no tienen la longitud correcta, añadimos ceros a la izquierda ya que podría generar un numero menor
  rHex = rHex.padStart(64, "0");
  sHex = sHex.padStart(64, "0");

  // Construir la firma con r, s y v (recoveryParam)
  const signature = {
    r: "0x" + rHex, // Prefijo 0x y r ajustado a 64 caracteres
    s: "0x" + sHex, // Prefijo 0x y s ajustado a 64 caracteres
    v: firma.recoveryParam + 27, // El valor de v es 27 o 28 en ECDSA
  };

  // Asignar valores r, s y v
  const { r, s, v } = signature;

  // Verificamos la firma antes de almacenarla
  const firmaValida = ec.verify(
    hashDocumentoFirmar, // El hash del documento
    { r: rHex, s: firma.s }, // La firma (r y s como objetos BigNumber)
    clavePublicaGen // La clave pública del firmante
  );

  // Si la firma es válida, se almacena en el contrato
  if (firmaValida) {
    console.log("La firma es válida. Procediendo a almacenar en el contrato.");

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
      clavePrivadaMetaMask
    );
    console.log("Transaccion firmada: ", signedTx);

    // Enviar la transacción
    const receipt = await web3.eth.sendSignedTransaction(
      signedTx.rawTransaction
    );

    //Hash de la transaccion para identificar el bloque luego
    const transactionHash = receipt.transactionHash;

    return { receipt, transactionHash };
  } else {
    console.log("Firma inválida. No se almacenará en el contrato.");
    return res.status(404).json({
      status: "Error",
      message: "Firma inválida. No se almacenará en el contrato...",
    });
  }
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

// Función para obtener los documentos firmados por userID
const obtenerDocumentosFirmadosPorUsuario = async (req, res) => {
  const { userID } = req.params; // userID enviado desde el frontend en los parámetros de la URL
  try {
    // Buscar todos los documentos con el userID especificado
    const documentos = await DocumentModel.find({ userID: userID });
    // Verificar si se encontraron documentos
    if (documentos.length === 0) {
      return res.status(404).json({
        message: "No se encontraron documentos firmados para este usuario.",
      });
    }
    // Enviar los documentos encontrados como respuesta
    res.status(200).json(documentos);
  } catch (error) {
    // Manejar errores
    console.error("Error al obtener documentos firmados:", error);
    res.status(500).json({ message: "Error al obtener documentos firmados." });
  }
};

// Funcion que se encarga del log de los documentos
async function registrarVerificacionDocumento(
  userID,
  firmanteID,
  documentID,
  nombreDocumento
) {
  try {
    // Validar que el usuario que verifica no sea el mismo que firmó
    if (userID === firmanteID) {
      console.log(
        "El usuario que verifica es el mismo que firmó el documento. No se registrará la verificación."
      );
      return; // Salir de la función sin registrar
    }

    const nuevaVerificacion = new VerificationModel({
      userID: userID,
      documentID: documentID,
      nombreDocumento: nombreDocumento,
      fechaVerificacion: new Date(), // Se guarda automáticamente con la fecha actual
      firmanteID: firmanteID,
    });

    await nuevaVerificacion.save();
    console.log("Verificación de documento registrada en la base de datos.");
  } catch (error) {
    console.error("Error al registrar la verificación:", error);
  }
}
// Función para obtener los documentos revisados por un usuario (Log de Documentos)
async function obtenerDocumentosRevisados(req, res) {
  const { firmanteID } = req.params; // El userID se pasa como parámetro en la URL

  try {
    // Buscar todos los logs de verificación del usuario en sesion, en este caso se guarda en firmanteID
    const logs = await VerificationModel.find({ firmanteID: firmanteID });
    if (logs.length === 0) {
      return res.status(404).json({
        status: "Error",
        message: "No se encontraron verificaciones para este usuario.",
      });
    }

    // Obtener todos los IDs de los usuarios desde los logs
    const userIDs = logs.map((log) => log.userID); // Obtener solo el userID

    // Obtener los datos de los usuarios correspondientes
    const usuarios = await UserModel.find({ userID: { $in: userIDs } }); // Busca todos los usuarios que coincidan

    // Convertir la lista de usuarios en un objeto para un acceso más fácil
    const usuariosMap = {};
    usuarios.forEach((usuario) => {
      usuariosMap[usuario.userID] = usuario.nombre; // Asumiendo que tienes un campo 'nombre'
    });

    // Agregar el nombre del usuario a cada log
    const logsConNombres = logs.map((log) => ({
      ...log._doc,
      nombre: usuariosMap[log.userID] || "Usuario desconocido", // Añadir nombre o valor por defecto
    }));

    // Enviar los logs como respuesta
    res.status(200).json({
      status: "OK",
      message: "Verificaciones encontradas",
      documentos: logsConNombres,
    });
  } catch (error) {
    console.error("Error al obtener los documentos revisados:", error);
    res.status(500).json({
      status: "Error",
      message: "Error interno del servidor",
    });
  }
}

// Función para obtener los datos de la transacción de ethereum (la firma) y decodificar el input data
async function obtenerFirmaTransaccion(transactionHash) {
  try {
    const transaction = await web3.eth.getTransaction(transactionHash);
    if (transaction) {
      console.log("Input Data:", transaction.input);

      // Definir los tipos de los parámetros de la función
      const paramTypes = ["bytes32", "address", "uint8", "bytes32", "bytes32"];

      // Decodifica el input data
      const decodedData = web3.eth.abi.decodeParameters(
        paramTypes,
        transaction.input.slice(10)
      ); // Eliminar el primer 0x y los 4 bytes de la firma de la función

      // Asignar los valores a variables individuales
      const firma = {
        hash: decodedData[0], // bytes32 hash del documento
        firmante: decodedData[1], // address firmante
        v: decodedData[2], // uint8 v
        r: decodedData[3], // bytes32 r
        s: decodedData[4], // bytes32 s
        timestamp: Date.now() / 1000, // Puedes asignar un timestamp si es necesario
      };

      return {
        status: "Success",
        message: "Firma recuperada con éxito.",
        firma,
      };
    } else {
      console.log("No se encontró la transacción.");
      return null;
    }
  } catch (error) {
    console.error("Error al obtener los datos de la transacción:", error);
    return null;
  }
}

// Función para verificar la firma con el hash del archivo
async function verificarFirmaDocumento(req, res) {
  try {
    // Validación del archivo cargado
    if (!req.file) {
      return res.status(400).send("No se ha subido ningún archivo.");
    }
    // ID del usuario que verifica el documento
    const userIDverficar = req.body.userID;

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
    const hashTransaccion = documentoExistente.blockchainTxHash; //Con esto podemos traer los datos de la blockchain directamente
    const userID = documentoExistente.userID;
    const user = await UserModel.findOne({ userID });

    const firmaTransaccion = await obtenerFirmaTransaccion(hashTransaccion);
    console.log("Firmas recuperadas por datos transaccion: ", firmaTransaccion);

    // Verificamos que la transacción haya sido exitosa al recuperar los datos de la firma
    if (firmaTransaccion.status !== "Success") {
      return res.status(400).json({
        status: "Error",
        message: "No se pudo recuperar la firma de la blockchain.",
      });
    }

    // Recuperamos los datos de la firma del blockchain
    const { v, r, s, timestamp } = firmaTransaccion.firma;

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

    // Registrar el log en la base de datos
    await registrarVerificacionDocumento(
      userIDverficar,
      userID,
      documentoExistente.documentID,
      documentoExistente.nombreDocumento
    );

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
    const { password, token2FA, userID, hashOriginal } = req.body;
    //Esto lo usamos para buscar si ya existe un hash asociado al documento en la BD, por si el usuario
    //Vuelve a subir un documento con la marca de la firma
    const hashOriginalBD = "0x" + hashOriginal;

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

    // Generar el `documentID` a partir del hash del archivo antes de agregarle la marca
    const documentID = parseInt(hashOriginal, 16).toString(36).slice(0, 16);

    // Buscar si el documento ya existe en la base de datos, si encuentra 1 de esos 2 quiere decir que ya se firmo (por documentID o hashDocumento)
    //Si encuentra el documentID es el archivo original y si encuentra por el hash es el archivo con la marca de la firma
    const documentoExistente = await DocumentModel.findOne({
      $or: [{ documentID }, { hashDocumento: hashOriginalBD }],
    });
    // Si existe, devolver un error
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

    // Firma de documento con el contrato inteligente y lo almacena
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
  obtenerDocumentosFirmadosPorUsuario,
  obtenerDocumentosRevisados,
};

export default recepcionDatos;
