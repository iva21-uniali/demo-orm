import { Request, Response, NextFunction } from "express";

/**
 * Sesión de usuario SIMULADA.
 *
 * En una aplicación real estos datos provendrían de una cookie o un token (JWT)
 * verificados por el servidor, NUNCA del cuerpo de la petición. Aquí representan a
 * la usuaria que ha iniciado sesión en el portal: Alicia (id #1).
 *
 * Los endpoints seguros usan `req.usuarioActual` para decidir a quién pueden
 * modificar. Esa es la defensa contra IDOR: aunque un atacante envíe otro `id` en
 * el cuerpo, el servidor solo toca el usuario de la sesión.
 */
export interface SesionUsuario {
  userId: number;
  username: string;
}

// Ampliamos el tipo Request de Express para exponer `usuarioActual` con tipos.
declare global {
  namespace Express {
    interface Request {
      usuarioActual?: SesionUsuario;
    }
  }
}

export function sesionSimulada(
  req: Request,
  _res: Response,
  next: NextFunction
): void {
  req.usuarioActual = { userId: 1, username: "alice" };
  next();
}
