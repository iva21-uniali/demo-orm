import { Router, Request, Response } from "express";
import { AppDataSource } from "../db/data-source";
import { User } from "../entities/User";
import {
  BuscarDirectorioDTO,
  ActualizarPerfilDTO,
  DISTINCT_ALLOWLIST,
} from "../validation/schemas";

/**
 * ===========================================================================
 *  API v2.0 — ENDPOINTS SEGUROS  (✅ así SÍ se debe programar)
 * ===========================================================================
 *  Misma funcionalidad, pero validando la entrada con Zod + lista blanca ANTES
 *  de tocar TypeORM, y atando las operaciones al usuario autenticado.
 */
export const rutasSeguras = Router();

const VERDE = "\x1b[32m";
const AMARILLO = "\x1b[33m";
const RESET = "\x1b[0m";
const separador = () => console.log(VERDE + "=".repeat(74) + RESET);

/** Formatea los errores de Zod en un único mensaje legible. */
function motivoZod(error: import("zod").ZodError): string {
  return error.issues.map((i) => `${i.path.join(".") || "payload"}: ${i.message}`).join(" | ");
}

// ---------------------------------------------------------------------------
//  ✅ Defensa CVE-2026-76848 — Zod enum + lista blanca
// ---------------------------------------------------------------------------
rutasSeguras.post("/directorio", async (req: Request, res: Response) => {
  separador();
  const parsed = BuscarDirectorioDTO.safeParse(req.body);
  if (!parsed.success) {
    const motivo = motivoZod(parsed.error);
    console.log(AMARILLO + "[BLOQUEADO POR ZOD/ALLOWLIST · 400]:" + RESET, motivo);
    separador();
    return res.status(400).json({ ok: false, error: motivo });
  }

  const { distinctOn } = parsed.data;
  try {
    const qb = AppDataSource.getRepository(User)
      .createQueryBuilder("user")
      .select(["user.id", "user.username", "user.fullName", "user.role", "user.department"])
      .where("user.visibleEnDirectorio = :vis", { vis: true });

    if (distinctOn) {
      // Solo llega a distinctOn la columna TRADUCIDA desde la lista blanca.
      qb.distinctOn([DISTINCT_ALLOWLIST[distinctOn]]);
    }

    console.log(VERDE + "[SQL SEGURO]:" + RESET, qb.getQuery());
    separador();
    const data = await qb.getMany();
    res.json({ ok: true, sql: qb.getQuery(), data });
  } catch {
    res.status(500).json({ ok: false, error: "Error interno del servidor" });
  }
});

// ---------------------------------------------------------------------------
//  ✅ Defensa CVE-2025-60542 + mass assignment + IDOR
// ---------------------------------------------------------------------------
rutasSeguras.post("/perfil", async (req: Request, res: Response) => {
  separador();
  const parsed = ActualizarPerfilDTO.safeParse(req.body);
  if (!parsed.success) {
    const motivo = motivoZod(parsed.error);
    console.log(AMARILLO + "[BLOQUEADO POR ZOD · 400]:" + RESET, motivo);
    separador();
    return res.status(400).json({ ok: false, error: motivo });
  }

  // Defensa IDOR: el usuario a modificar sale de la SESIÓN, nunca del body.
  const idObjetivo = req.usuarioActual!.userId;

  // Defensa mass assignment / CVE-2025-60542: update() con columnas EXPLÍCITAS.
  // Aunque el DTO ya es estricto, aquí solo escribimos el campo permitido.
  const repo = AppDataSource.getRepository(User);
  await repo.update({ id: idObjetivo }, { department: parsed.data.department });

  console.log(VERDE + `[PERFIL ACTUALIZADO] usuario #${idObjetivo} -> department = "${parsed.data.department}"` + RESET);
  separador();

  const data = await repo.find({
    select: ["id", "username", "fullName", "role", "department"],
    where: { visibleEnDirectorio: true },
  });
  res.json({ ok: true, data });
});
