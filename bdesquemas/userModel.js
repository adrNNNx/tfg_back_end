import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    userID: {
      type: String,
      required: true,
      unique: true,
    },
    nombre: {
      type: String,
      required: true,
      unique: true,
    },
    nombreReal: {
      type: String,
      required: true,
    },
    apellido: {
      type: String,
      required: true,
    },
    contraseña: {
      type: String,
      required: true,
    },
    clavePrivadaCifrada: {
      type: String,
      required: true,
    },
    clavePublica: {
      type: String,
      required: true,
    },
    saltClavePrivada: {
      type: String,
      required: true,
    },
    saltCifrado: {
      type: String,
      required: true,
    },
    iv: {
      type: String,
      required: true,
    },
    secret2FA: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
); // Para registrar las fechas de creación y actualización automáticas

const UserModel = mongoose.model("User", userSchema);

export default UserModel;
