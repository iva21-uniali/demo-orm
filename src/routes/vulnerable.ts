import { Router, Request, Response } from "express";
import { AppDataSource } from "../db/data-source";
import { User } from "../entities/User";
import { reproducirSaveVulnerableMysql } from "../db/reproduction";

/**
 * ===========================================================================
 *  API v1.0 — ENDPOINTS VULNERABLES  (⚠️ así NO se debe programar)
 * ===========================================================================
 *  Pasan la entrada del cliente a TypeORM sin validarla. Demuestran que un ORM
 *  no te protege por sí solo.
 */
export const rutasVulnerables = Router();

const ROJO = "\x1b[31m";
const AMARILLO = "\x1b[33m";
const RESET = "\x1b[0m";
const separador = () => console.log(ROJO + "=".repeat(74) + RESET);

// ---------------------------------------------------------------------------
//  ❌ CVE-2026-76848 — distinctOn sin lista blanca
// ---------------------------------------------------------------------------
/**
 * El desarrollador NO concatena strings en el WHERE (usa un filtro fijo), así que
 * "cree" estar a salvo. Pero pasa la entrada del cliente directamente a
 * `qb.distinctOn([...])`, y TypeORM la interpola en el SELECT sin lista blanca.
 */
rutasVulnerables.post("/directorio", async (req: Request, res: Response) => {
  const distinctOn: string = (req.body?.distinctOn ?? "").toString();
  separador();
  console.log(ROJO + "[VULNERABLE · CVE-2026-76848] distinctOn:" + RESET, JSON.stringify(distinctOn));

  try {
    const qb = AppDataSource.getRepository(User)
      .createQueryBuilder("user")
      .where("user.visibleEnDirectorio = 1");

    if (distinctOn) {
      qb.distinctOn([distinctOn]); // <-- ❌ entrada sin validar: punto de inyección
    }

    const sql = qb.getQuery();
    console.log(AMARILLO + "[SQL GENERADO POR TYPEORM]:" + RESET, sql);
    separador();

    // En uso normal, getMany() devuelve entidades ya mapeadas (columnas id, username...).
    // Cuando la inyección comenta el resto de la consulta, getMany() no mapea nada;
    // entonces ejecutamos el SQL crudo para exponer las columnas que el atacante robó.
    let data: unknown[] = await qb.getMany();
    if (distinctOn && data.length === 0) {
      data = await AppDataSource.query(sql);
    }

    res.json({ ok: true, sql, data });
  } catch (err: any) {
    console.log(ROJO + "[ERROR SQL]:" + RESET, err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
//  ❌ CVE-2025-60542 — repository.save(req.body) sin validar
// ---------------------------------------------------------------------------
/**
 * El desarrollador vuelca `req.body` entero en el repositorio. Esto abre TRES
 * problemas a la vez, que la API v2.0 resolverá uno a uno:
 *   1. CVE-2025-60542 : un objeto anidado inyecta columnas extra en el UPDATE.
 *   2. Mass assignment: acepta cualquier campo, p. ej. {"id":1,"role":"admin"}.
 *   3. IDOR           : confía en `body.id`, así que puedes modificar a OTRO usuario.
 */
rutasVulnerables.post("/perfil", async (req: Request, res: Response) => {
  const body: Record<string, any> = { ...(req.body ?? {}) };
  separador();
  console.log(ROJO + "[VULNERABLE · repository.save(req.body)]:" + RESET, JSON.stringify(body));

  try {
    const repo = AppDataSource.getRepository(User);

    // ¿Alguna propiedad es un objeto JSON anidado? -> CVE-2025-60542.
    const campoAnidado = Object.entries(body).find(
      ([, v]) => v !== null && typeof v === "object" && !Array.isArray(v)
    );

    if (campoAnidado) {
      // Reproducción FIEL con la librería real `sqlstring` (ver db/reproduction.ts).
      const [, objeto] = campoAnidado;
      const sql = await reproducirSaveVulnerableMysql(objeto as Record<string, unknown>, Number(body.id));
      console.log(AMARILLO + "[CVE-2025-60542 · UPDATE real de TypeORM+sqlstring en MySQL]:" + RESET, sql);
    } else {
      // Sin objeto anidado: save() normal. OJO: acepta cualquier campo (mass
      // assignment) y confía en body.id (IDOR).
      await repo.save(body);
    }

    separador();
    const data = await repo.find({ where: { visibleEnDirectorio: true } });
    res.json({ ok: true, data });
  } catch (err: any) {
    console.log(ROJO + "[ERROR EN SAVE()]:" + RESET, err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});
