import path from "path";
import express from "express";
import { sesionSimulada } from "./security/session";
import { rutasVulnerables } from "./routes/vulnerable";
import { rutasSeguras } from "./routes/secure";

/**
 * Construye la aplicación Express y conecta todas las piezas.
 *
 * Rutas:
 *   POST /api/vulnerable/directorio | /perfil   -> API v1.0 (sin validar)
 *   POST /api/seguro/directorio     | /perfil   -> API v2.0 (Zod + lista blanca)
 * El frontend (carpeta public/) alterna entre ambas con el botón v1.0 / v2.0.
 */
export function crearApp(): express.Express {
  const app = express();

  app.use(express.json());
  app.use(sesionSimulada); // inyecta req.usuarioActual (sesión simulada)

  app.use("/api/vulnerable", rutasVulnerables);
  app.use("/api/seguro", rutasSeguras);

  // Interfaz web estática.
  app.use(express.static(path.join(__dirname, "..", "public")));

  return app;
}
