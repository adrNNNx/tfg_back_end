import mongoose from "mongoose";

const documentoFirmadoSchema = new mongoose.Schema({
  documentID: {
    type: String,
    required: true,
    unique: true,
  },
  userID: {
    type: String,
    required: true,
  },
  nombreDocumento: {
    type: String,
    required: true,
  },
  fechaFirma: {
    type: Date,
    required: true,
    default: Date.now,
  },
  hashDocumento: {
    type: String,
    required: true,
  },
  blockchainTxHash: {
    type: String,
    required: true,
  },
});

const DocumentoFirmado = mongoose.model("signed_documents", documentoFirmadoSchema);

export default DocumentoFirmado;