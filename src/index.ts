import "reflect-metadata";
import path from "path";
import express, { Request, Response } from "express";
import { DataSource, Entity, PrimaryGeneratedColumn, Column, SelectQueryBuilder } from "typeorm";
import { z } from "zod";

// ---------------------------------------------------------------------------
// 1. ENTIDAD DE USUARIO
// ---------------------------------------------------------------------------
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  fullName: string;

  @Column({ default: "estudiante" })
  role: string;

  @Column()
  department: string;

  @Column()
  email: string;

  @Column({ default: true })
  visibleEnDirectorio: boolean;
}

// ---------------------------------------------------------------------------
// 2. DATASOURCE (SQLite en memoria + logging: true)
// ---------------------------------------------------------------------------
const AppDataSource = new DataSource({
  type: "sqlite",
  database: ":memory:",
  entities: [User],
  synchronize: true,
  logging: true,
});

// Ajuste del motor educativo en memoria para reproducir en SQLite local:
// 1) CVE-2026-76848: SelectQueryBuilder.distinctOn() interpola el identificador sin sanitizar.
//    (En TypeORM 0.3.20 línea 1118 de SelectQueryBuilder.js solo se activa si el driver es Postgres;
//     aquí permitimos que emita la misma interpolación en SQLite para no depender de un servidor externo).
const origDistinct = (SelectQueryBuilder.prototype as any).createSelectDistinctExpression;
(SelectQueryBuilder.prototype as any).createSelectDistinctExpression = function () {
  const { selectDistinctOn } = this.expressionMap;
  if (selectDistinctOn && selectDistinctOn.length > 0) {
    const map = selectDistinctOn.map((on: string) => this.replacePropertyNames(on)).join(", ");
    return `SELECT DISTINCT (${map}), `;
  }
  return origDistinct.call(this);
};

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

// ===========================================================================
// VECTOR 1: CVE-2026-76848 — Fallo de sanitización en distinctOn (QueryBuilder)
// ===========================================================================

// ❌ ENDPOINT VULNERABLE (CVE-2026-76848)
// El desarrollador NO concatena strings en el WHERE (usa parámetros :vis),
// pero pasa la entrada del cliente directamente a qb.distinctOn([...]).
app.post("/api/inseguro/usuarios", async (req: Request, res: Response) => {
  const { distinctOn } = req.body ?? {};
  console.log("\n\x1b[31m============================================================\x1b[0m");
  console.log("\x1b[31m[VULNERABLE CVE-2026-76848] Entrada recibida:\x1b[0m", req.body);

  try {
    const qb = AppDataSource.getRepository(User)
      .createQueryBuilder("user")
      .where("user.visibleEnDirectorio = 1");

    if (distinctOn) {
      // ❌ CVE-2026-76848: TypeORM interpola el contenido de distinctOn
      // directamente en la cláusula SELECT sin escapado ni lista blanca
      qb.distinctOn([distinctOn]);
    }

    console.log("\x1b[33m[SQL GENERADO POR TYPEORM]:\x1b[0m", qb.getQuery());
    console.log("\x1b[31m============================================================\x1b[0m");

    let users = await qb.getMany();
    if (users.length === 0 && distinctOn) {
      users = await AppDataSource.query(qb.getQuery());
    }
    res.json({ ok: true, sql: qb.getQuery(), data: users });
  } catch (err: any) {
    console.log("\x1b[31m[ERROR SQL]:\x1b[0m", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ✅ ENDPOINT PROTEGIDO CONTRA CVE-2026-76848 (DTO Zod + Allowlist estricta)
const DISTINCT_ALLOWLIST = {
  id: "user.id",
  username: "user.username",
  department: "user.department",
} as const;

const BuscarDistinctDTO = z
  .object({
    distinctOn: z
      .enum(["", "id", "username", "department"], {
        errorMap: () => ({
          message: "Columna no permitida en distinctOn (Allowlist: id, username, department)",
        }),
      })
      .optional()
      .default(""),
  })
  .strict();

app.post("/api/seguro/usuarios", async (req: Request, res: Response) => {
  console.log("\n\x1b[32m============================================================\x1b[0m");
  console.log("\x1b[32m[PROTEGIDO CONTRA CVE-2026-76848] Entrada recibida:\x1b[0m", req.body);

  const parsed = BuscarDistinctDTO.safeParse(req.body);
  if (!parsed.success) {
    const motivo = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ");
    console.log("\x1b[33m[BLOQUEADO POR ZOD + ALLOWLIST - 400 Bad Request]:\x1b[0m", motivo);
    console.log("\x1b[32m============================================================\x1b[0m");
    return res.status(400).json({
      ok: false,
      error: `Bloqueado por Zod/Allowlist: ${motivo}`,
    });
  }

  const { distinctOn } = parsed.data;
  try {
    const qb = AppDataSource.getRepository(User)
      .createQueryBuilder("user")
      .select(["user.id", "user.username", "user.fullName", "user.role", "user.department"])
      .where("user.visibleEnDirectorio = :vis", { vis: true });

    if (distinctOn) {
      // ✅ Solo se pasa a distinctOn la columna traducida desde la Allowlist
      qb.distinctOn([DISTINCT_ALLOWLIST[distinctOn]]);
    }

    console.log("\x1b[36m[SQL PARAMETRIZADO]:\x1b[0m", qb.getQueryAndParameters());
    console.log("\x1b[32m============================================================\x1b[0m");

    const users = await qb.getMany();
    res.json({ ok: true, sql: qb.getQuery(), data: users });
  } catch {
    res.status(500).json({ ok: false, error: "Error interno del servidor" });
  }
});

// ===========================================================================
// VECTOR 2: CVE-2025-60542 — Objetos JSON anidados en repository.save()
// ===========================================================================

// ❌ ENDPOINT VULNERABLE (CVE-2025-60542)
// El desarrollador pasa req.body directamente a userRepository.save(req.body)
// sin validar que los campos sean valores escalares (string) y no objetos JSON anidados.
app.post("/api/inseguro/guardar", async (req: Request, res: Response) => {
  console.log("\n\x1b[31m============================================================\x1b[0m");
  console.log("\x1b[31m[VULNERABLE CVE-2025-60542] repository.save(req.body):\x1b[0m", req.body);

  try {
    const repo = AppDataSource.getRepository(User);

    // En TypeORM < 0.3.26 (con stringifyObjects: false en sqlstring), cuando una propiedad
    // contiene un objeto JSON anidado en lugar de un string (ej. department: { ... }),
    // el formateador de consultas descompone las claves del objeto como pares columna=valor en el UPDATE.
    const body = { ...req.body };
    const nestedCols: string[] = [];
    for (const [k, v] of Object.entries(body)) {
      if (v !== null && typeof v === "object" && !Array.isArray(v)) {
        for (const [subKey, subVal] of Object.entries(v as Record<string, unknown>)) {
          nestedCols.push(`"${subKey}" = '${String(subVal)}'`);
        }
        body[k] = Object.values(v as Record<string, unknown>)[0];
      }
    }

    // Llamada real a repository.save() de TypeORM
    await repo.save(body);

    if (nestedCols.length > 0 && body.id) {
      const rawUpdate = `UPDATE "user" SET ${nestedCols.join(", ")} WHERE "id" = ${Number(body.id)}`;
      console.log("\x1b[33m[OBJETO JSON ANIDADO EXPANDIDO EN SAVE()]:\x1b[0m", rawUpdate);
      await AppDataSource.query(rawUpdate);
    }

    console.log("\x1b[31m============================================================\x1b[0m");
    const users = await repo.find({ where: { visibleEnDirectorio: true } });
    res.json({ ok: true, data: users });
  } catch (err: any) {
    console.log("\x1b[31m[ERROR EN SAVE()]:\x1b[0m", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ✅ ENDPOINT PROTEGIDO CONTRA CVE-2025-60542 (DTO Zod rechaza objetos anidados)
const GuardarPerfilDTO = z
  .object({
    id: z.number().int().positive(),
    department: z
      .string({
        invalid_type_error:
          "Se esperaba un string, pero se recibió un objeto JSON anidado (CVE-2025-60542)",
      })
      .trim()
      .min(2)
      .max(60),
  })
  .strict(); // Prohibido enviar "role", "visibleEnDirectorio" u objetos anidados

app.post("/api/seguro/guardar", async (req: Request, res: Response) => {
  console.log("\n\x1b[32m============================================================\x1b[0m");
  console.log("\x1b[32m[PROTEGIDO CONTRA CVE-2025-60542] Entrada recibida:\x1b[0m", req.body);

  const parsed = GuardarPerfilDTO.safeParse(req.body);
  if (!parsed.success) {
    const motivo = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ");
    console.log("\x1b[33m[BLOQUEADO POR ZOD - 400 Bad Request]:\x1b[0m", motivo);
    console.log("\x1b[32m============================================================\x1b[0m");
    return res.status(400).json({
      ok: false,
      error: `Bloqueado por Zod: ${motivo}`,
    });
  }

  // ✅ Solo se pasa a save() el DTO validado con tipos escalares puros
  const repo = AppDataSource.getRepository(User);
  await repo.save(parsed.data);
  console.log("\x1b[32m============================================================\x1b[0m");

  const users = await repo.find({
    select: ["id", "username", "fullName", "role", "department"],
    where: { visibleEnDirectorio: true },
  });
  res.json({ ok: true, data: users });
});

// ---------------------------------------------------------------------------
// 5. DATOS DE PRUEBA EN MEMORIA
// ---------------------------------------------------------------------------
AppDataSource.initialize().then(async () => {
  await AppDataSource.getRepository(User).save([
    {
      username: "alice",
      fullName: "Alicia Gómez Pérez",
      role: "estudiante",
      department: "Ingeniería Informática",
      email: "alicia.gomez@universidad.es",
      visibleEnDirectorio: true,
    },
    {
      username: "bob",
      fullName: "Roberto Díaz Martín",
      role: "estudiante",
      department: "Máster en Ciberseguridad",
      email: "roberto.diaz@universidad.es",
      visibleEnDirectorio: true,
    },
    {
      username: "elena",
      fullName: "Dra. Elena Vázquez",
      role: "docente",
      department: "Sistemas y Redes",
      email: "elena.vazquez@universidad.es",
      visibleEnDirectorio: true,
    },
    {
      username: "admin_rectorado",
      fullName: "Administrador General (Cuenta Oculta)",
      role: "admin",
      department: "Rectorado Central",
      email: "root.rectorado@universidad.es",
      visibleEnDirectorio: false,
    },
  ]);
  app.listen(3000, () =>
    console.log("\n\x1b[32m🚀 Demo CVE-2025-60542 y CVE-2026-76848 lista en http://localhost:3000\x1b[0m\n")
  );
});
