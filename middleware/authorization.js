import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";
import UserModel from "../bdesquemas/userModel.js";

dotenv.config();

function soloAdmin(req, res, next) {
  const logueado = revisarCookie(req);
  if (logueado) return next();
  return res.redirect("/login");
}


async function revisarCookie(req) {
  try {
    // Verificar si la cookie existe antes de proceder
    if (!req.headers.cookie) {
      console.log('No hay cookies en la solicitud');
      return false;
    }

    // Separar la cookie para poder leerla
    const cookieJWT = req.headers.cookie
      .split('; ')
      .find(cookie => cookie.startsWith('jwt='))
      ?.slice(4); // Usa el operador de encadenamiento opcional para evitar errores si no se encuentra la cookie

    if (!cookieJWT) {
      console.log('No se encontró el token en las cookies');
      return false;
    }

    console.log('Cookie JWT encontrada:', cookieJWT);

    // Decodificar la cookie y comparar con la clave secreta
    const decodificada = jsonwebtoken.verify(cookieJWT, process.env.JWT_SECRET);

    console.log('Token decodificado:', decodificada); 
    
    // Revisar si el usuario existe en la base de datos
    const usuarioArevisar = await UserModel.findOne({ nombre: decodificada.user });

    if (!usuarioArevisar) {
      return false;
    }

    return true;
  } catch (error) {
    console.error('Error al revisar la cookie:', error);
    return false;
  }
}

const middlewares = {
  soloAdmin,
  revisarCookie,
};

export default middlewares;
