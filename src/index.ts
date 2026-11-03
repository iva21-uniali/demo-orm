import "reflect-metadata";
import { AppDataSource } from "./db/data-source";
import { habilitarReproduccionDistinctOn } from "./db/reproduction";
import { cargarDatosDePrueba } from "./db/seed";
import { crearApp } from "./app";

/**
 * Punto de arranque de la demo.
 *
 * Secuencia:
 *   1. Habilita la reproducción didáctica del CVE-2026-76848 (ver db/reproduction.ts).
 *   2. Inicializa la base SQLite en memoria y carga los datos de prueba.
 *   3. Levanta el servidor Express en http://localhost:3000.
 */
const VERDE = "\x1b[32m";
const RESET = "\x1b[0m";
const PUERTO = 3000;

async function main(): Promise<void> {
  habilitarReproduccionDistinctOn();

  await AppDataSource.initialize();
  await cargarDatosDePrueba();

  const app = crearApp();
  app.listen(PUERTO, () => {
    console.log(
      `\n${VERDE}🚀 Demo CVE-2025-60542 y CVE-2026-76848 lista en http://localhost:${PUERTO}${RESET}\n`
    );
  });
}

main().catch((err) => {
  console.error("Error al arrancar la demo:", err);
  process.exit(1);
});
