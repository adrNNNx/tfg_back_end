import mongoose from "mongoose";

const verificationLogSchema = new mongoose.Schema({
  userID: {
    type: String,
    required: true,
  },
  documentID: {
    type: String, // Cambia de ObjectId a String si estás usando UUIDs
    required: true,
  },
  nombreDocumento: { type: String, required: true },
  fechaVerificacion: { type: Date, default: Date.now },
  firmanteID: { type: String, required: true },
});

const VerificationLog = mongoose.model(
  "VerificationLog",
  verificationLogSchema
);

export default VerificationLog;
