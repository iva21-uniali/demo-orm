import SqlString from "sqlstring";
import { SelectQueryBuilder } from "typeorm";
import { AppDataSource } from "./data-source";

/**
 * ============================================================================
 *  CAPA DE REPRODUCCIÓN DIDÁCTICA  —  LÉEME (honestidad del montaje)
 * ============================================================================
 *
 *  Los dos CVE son REALES y están publicados, pero cada uno solo se dispara de
 *  forma NATIVA sobre un motor de base de datos concreto:
 *
 *    · CVE-2026-76848 (distinctOn)     -> nativo SOLO en PostgreSQL.
 *    · CVE-2025-60542 (save / update)  -> nativo SOLO en MySQL/mysql2 con TypeORM < 0.3.26.
 *
 *  Esta demo usa SQLite en memoria para poder ejecutarse sin servidores externos.
 *  Por eso, para verlos en acción aquí, hay que "traer" el comportamiento
 *  vulnerable al entorno SQLite. Este módulo AÍSLA esa reproducción y deja claro,
 *  en cada caso, qué parte es CÓDIGO REAL de TypeORM/sqlstring (la causa raíz del
 *  fallo) y qué parte añadimos nosotros solo para que sea observable en SQLite.
 *
 *  Resumen honesto para la defensa del máster:
 *    - La LÓGICA vulnerable es idéntica a la de la librería real.
 *    - Lo único "artificial" es ejecutarla sobre SQLite en vez de sobre el motor
 *      donde el bug está activo por defecto.
 */

// ---------------------------------------------------------------------------
//  CVE-2026-76848  ·  SelectQueryBuilder.distinctOn()
// ---------------------------------------------------------------------------
/**
 * En el código fuente REAL de TypeORM (query-builder/SelectQueryBuilder.js,
 * método `createSelectDistinctExpression`, ~línea 1116) el fragmento vulnerable es:
 *
 *   if (DriverUtils.isPostgresFamily(driver) && selectDistinctOn.length > 0) {
 *     const map = selectDistinctOn
 *       .map((on) => this.replacePropertyNames(on))   // <-- traduce alias, NO valida ni escapa
 *       .join(", ");
 *     select = `SELECT DISTINCT ON (${map}) `;         // <-- interpola el texto tal cual
 *   }
 *
 * Es decir: `replacePropertyNames` NO aplica ninguna lista blanca ni escapado;
 * pega la entrada directamente en la cláusula SELECT. La única barrera es el
 * `if (isPostgresFamily)`, de modo que sobre SQLite esa rama nunca se ejecuta.
 *
 * Aquí sobreescribimos ese método para que emita la MISMA interpolación insegura
 * también en SQLite. La lógica (replacePropertyNames sin lista blanca) es idéntica
 * a la de TypeORM; lo único que quitamos es el "candado" que la limita a Postgres.
 */
export function habilitarReproduccionDistinctOn(): void {
  const proto = SelectQueryBuilder.prototype as any;
  const metodoOriginal = proto.createSelectDistinctExpression;

  proto.createSelectDistinctExpression = function (this: any): string {
    const { selectDistinctOn } = this.expressionMap;
    if (selectDistinctOn && selectDistinctOn.length > 0) {
      // === idéntico a la rama Postgres real de TypeORM (sin sanitizar) ===
      const map = selectDistinctOn
        .map((on: string) => this.replacePropertyNames(on))
        .join(", ");
      return `SELECT DISTINCT (${map}), `;
    }
    return metodoOriginal.call(this);
  };
}

// ---------------------------------------------------------------------------
//  CVE-2025-60542  ·  objeto JSON anidado en repository.save() / update()
// ---------------------------------------------------------------------------
/**
 * Causa raíz: el driver MySQL de TypeORM delega la interpolación de parámetros en
 * la librería `sqlstring`, con la opción `stringifyObjects` en `false` (su valor
 * por defecto en TypeORM < 0.3.26). Con esa opción, cuando un parámetro es un
 * OBJETO, sqlstring NO lo convierte a texto: lo EXPANDE en pares `columna = valor`.
 *
 *   SqlString.format("?", [{ department: "Robotica", role: "admin" }], false)
 *     => `department` = 'Robotica', `role` = 'admin'
 *
 * Esa expansión es exactamente lo que permite inyectar una columna extra (`role`)
 * dentro de un UPDATE que solo debía tocar `department`.
 *
 * Esta función usa la LIBRERÍA REAL `sqlstring` (la misma que causa el CVE) para
 * construir el UPDATE expandido y lo ejecuta sobre SQLite, que acepta
 * identificadores entre backticks. El driver nativo de SQLite NO pasa por
 * sqlstring, por eso tenemos que invocarla explícitamente para reproducir el bug.
 *
 * Devuelve el SQL ejecutado (para poder registrarlo en el log del endpoint).
 */
export async function reproducirSaveVulnerableMysql(
  objetoAnidado: Record<string, unknown>,
  id: number
): Promise<string> {
  // stringifyObjects = false (3er argumento) -> la expansión peligrosa del CVE.
  const asignacionesExpandidas = SqlString.format("?", [objetoAnidado], false);
  const sql = `UPDATE \`user\` SET ${asignacionesExpandidas} WHERE \`id\` = ${Number(id)}`;
  await AppDataSource.query(sql);
  return sql;
}
