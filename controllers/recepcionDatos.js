import crypto from "crypto";

const hashArchivo = async (buffer) => {
  return crypto.createHash("sha256").update(buffer).digest("hex"); // Cambia 'sha256' si necesitas otro algoritmo
};

async function credenciales_documentos_hash(req, res) {
  // Endpoint para recibir el archivo y los datos del formulario
  try {
    const { privateKey, password, token2FA } = req.body;

    // Validación
    if (!req.file) {
      return res.status(400).send("No se ha subido ningún archivo.");
    }

    // Lógica para hash del archivo
    const hash = await hashArchivo(req.file.buffer); // Usa req.file.buffer para acceder al contenido del archivo

    // Aquí podrías enviar el hash a tu contrato inteligente
    console.log("Hash del archivo:", hash);
    console.log("Datos recibidos:", { privateKey, password, token2FA });

    // Respuesta al cliente
    res
      .status(200)
      .send({ message: "Archivo y datos recibidos exitosamente.", hash });
  } catch (error) {
    console.error("Error al procesar el archivo:", error);
    res.status(500).send("Error interno del servidor");
  }
}

const recepcionDatos = {
  credenciales_documentos_hash,
};

export default recepcionDatos;
