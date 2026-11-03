import { z } from "zod";

/**
 * Esquemas de validación de entrada (Zod).
 *
 * Son el CORAZÓN de la defensa: validan la entrada del usuario ANTES de que
 * llegue a TypeORM. La tesis de la demo es que el ORM no basta; esta capa es la
 * que de verdad cierra las dos inyecciones.
 */

// ---------------------------------------------------------------------------
//  Defensa CVE-2026-76848  ·  lista blanca de columnas para distinctOn
// ---------------------------------------------------------------------------
/**
 * Un nombre de columna NO se puede parametrizar con `?` en SQL, así que la única
 * defensa válida es una LISTA BLANCA: solo se aceptan estos valores conocidos, y
 * cada uno se traduce a su identificador de columna real. Nunca se pasa texto
 * libre del usuario a `distinctOn`.
 */
export const DISTINCT_ALLOWLIST = {
  id: "user.id",
  username: "user.username",
  department: "user.department",
} as const;

export type ColumnaDistinctPermitida = keyof typeof DISTINCT_ALLOWLIST;

/** DTO del directorio: `distinctOn` solo puede ser una columna de la lista blanca. */
export const BuscarDirectorioDTO = z
  .object({
    distinctOn: z
      .enum(["", "id", "username", "department"], {
        errorMap: () => ({
          message:
            "Columna no permitida en distinctOn (lista blanca: id, username, department)",
        }),
      })
      .optional()
      .default(""),
  })
  .strict(); // rechaza cualquier campo no declarado

// ---------------------------------------------------------------------------
//  Defensa CVE-2025-60542 (+ mass assignment)  ·  perfil
// ---------------------------------------------------------------------------
/**
 * DTO de actualización de perfil. Defiende tres cosas a la vez:
 *   1. `department: z.string()` -> rechaza objetos JSON anidados    (CVE-2025-60542).
 *   2. `.strict()`              -> rechaza claves extra como `role` (mass assignment).
 *   3. NO incluye `id`          -> el usuario a modificar se toma de la sesión
 *                                   autenticada, no del cuerpo de la petición (IDOR).
 */
export const ActualizarPerfilDTO = z
  .object({
    department: z
      .string({
        invalid_type_error:
          "Se esperaba un string, pero se recibió un objeto JSON anidado (CVE-2025-60542)",
      })
      .trim()
      .min(2)
      .max(60),
  })
  .strict();
