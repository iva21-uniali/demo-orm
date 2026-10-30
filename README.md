# Demo Universitaria: CVE-2025-60542 y CVE-2026-76848 en TypeORM

Proyecto educativo en local (`Node.js + Express + TypeScript + TypeORM + SQLite :memory:`) que reproduce en vivo las dos vulnerabilidades reales de TypeORM:

1. **CVE-2026-76848**: Fallo de sanitización en `distinctOn` dentro de `SelectQueryBuilder`.
2. **CVE-2025-60542**: Inyección SQL mediante objetos JSON anidados pasados a `repository.save()`.

---

## 1. Arranque rápido (con Docker o con Node local)

### Opción A: Con Docker (recomendado para no depender de versiones de Node)

```bash
docker compose up --build
```
*(Para apagarlo y reiniciar la base de datos en memoria: `Ctrl + C` y `docker compose down`).*

### Opción B: Con Node.js en local

```bash
npm install
npm start
```

- Abre **http://localhost:3000** a la izquierda de la pantalla.
- Deja la **terminal** a la derecha para ver las consultas SQL que construye TypeORM (`logging: true`).

---

## 2. Guion de pruebas en vivo (en `http://localhost:3000`)

Arriba a la derecha, junto al perfil de `Alicia Gómez`, está el botoncillo discreto de versión:
- **`🟠 API v1.0`** = Modo Vulnerable (por defecto al abrir la web).
- **`🟢 API v2.0`** = Modo Protegido (Zod + Allowlist).

### Prueba A — CVE-2026-76848 (`qb.distinctOn()` en `QueryBuilder`)

En `node_modules/typeorm/query-builder/SelectQueryBuilder.js` (líneas 1118–1121), el método oficial `qb.distinctOn([...])` interpola los elementos del array directamente dentro de `SELECT DISTINCT (...)` sin escaparlos ni validarlos contra una lista blanca.

- **Dónde escribir**: en el buscador de la derecha, encima de la tabla (*"Agrupar vista por campo..."*).

1. **Uso normal (`🟠 API v1.0`)**:
   - Escribe: `department` y pulsa **Filtrar vista**.
   - En la terminal verás: `SELECT DISTINCT ("user"."department"), "user"."id" ... WHERE "user"."visibleEnDirectorio" = 1`.
2. **Explotación del CVE-2026-76848 (`🟠 API v1.0`)**:
   - En ese mismo buscador, escribe:
     `1), * FROM user WHERE role='admin' --`
   - Pulsa **Filtrar vista**.
   - **Qué ocurre**: TypeORM incrusta ese texto dentro de `SELECT DISTINCT (1), * FROM user WHERE role='admin' --...)`, comentando el resto de la consulta original y devolviendo en la tabla la cuenta oculta **`@admin_rectorado`** (`visibleEnDirectorio = 0`).
3. **Remediación (`🟢 API v2.0`)**:
   - Haz clic en el botoncillo **`API v1.0`** de arriba a la derecha para cambiarlo a **`🟢 API v2.0`**, escribe lo mismo y pulsa **Filtrar vista**.
   - **Qué ocurre**: Zod y `DISTINCT_ALLOWLIST` bloquean cualquier valor fuera de la lista blanca (`id`, `username`, `department`) devolviendo **HTTP 400 Bad Request** sin ejecutar ninguna consulta SQL.

---

### Prueba B — CVE-2025-60542 (Objetos JSON anidados en `repository.save()`)

En TypeORM (< 0.3.26), cuando el desarrollador pasa `req.body` directamente a `await userRepository.save(req.body)` sin validar que las propiedades sean tipos primitivos (`string`), enviar un **objeto JSON anidado** dentro de una propiedad provoca que el formateador de consultas descomponga las claves del objeto como asignaciones `columna = valor` dentro del `UPDATE`.

- **Dónde escribir**: en la columna izquierda (*"Mi Perfil Académico"*), en el campo **Departamento / Especialidad**.

1. **Uso normal (`🟠 API v1.0`)**:
   - Escribe un texto normal: `Robótica` y pulsa **Guardar cambios**.
   - **Qué ocurre**: El departamento de `@alice` pasa a ser `Robótica` y su rol sigue siendo `estudiante`.
2. **Explotación del CVE-2025-60542 (`🟠 API v1.0`)**:
   - En esa misma caja **Departamento / Especialidad**, escribe este **objeto JSON anidado**:
     `{"department":"Robótica","role":"admin"}`
   - Pulsa **Guardar cambios**.
   - **Qué ocurre**: El objeto JSON anidado se expande en la sentencia `UPDATE "user" SET "department" = 'Robótica', "role" = 'admin' WHERE "id" = 1` y en la tabla de la derecha verás que **Alicia (`@alice`) se ha convertido en `admin`** (fila resaltada en rojo).
3. **Remediación (`🟢 API v2.0`)**:
   - Cambia el botoncillo superior derecho a **`🟢 API v2.0`** y vuelve a pulsar **Guardar cambios** con ese mismo objeto JSON anidado.
   - **Qué ocurre**: El esquema `GuardarPerfilDTO` de Zod exige `department: z.string()`. Al detectar un objeto JSON anidado en vez de un string, rechaza la petición con **HTTP 400 Bad Request (`Se esperaba un string, pero se recibió un objeto JSON anidado`)** antes de llegar a `repository.save()`.

---

## 3. Explicación sencilla: ¿Por qué funcionan estas dos inyecciones por debajo?

### A) ¿Por qué funciona la de `distinctOn` (`CVE-2026-76848`)?

1. **La limitación del estándar SQL**:
   En SQL, los **valores** (como el nombre `'alice'`) se pueden enviar como parámetros separados con `?`, pero los **nombres de columnas** (como `department` o `id`) **no admiten `?`** en SQL.
2. **El error interno de TypeORM**:
   Cuando el programador llama a `qb.distinctOn([entrada])`, TypeORM asume que ese dato lo ha escrito el propio programador y lo pega tal cual dentro del paréntesis del `SELECT DISTINCT (...)`:
   ```sql
   SELECT DISTINCT ( <LO_QUE_ESCRIBAS_AQUÍ> ), "user"."id", "user"."username"...
   FROM "user" WHERE "user"."visibleEnDirectorio" = 1
   ```
3. **Qué hace pieza por pieza lo que escribimos (`1), * FROM user WHERE role='admin' --`)**:
   - **`1)`**: Cierra el paréntesis que TypeORM había dejado abierto en `SELECT DISTINCT (`.
   - **`, * FROM user WHERE role='admin'`**: Añade el resto de una consulta nueva pidiendo todas las columnas (`*`) de la tabla `user` donde el rol sea `'admin'`.
   - **`--`**: Es el símbolo de comentario en SQL. Hace que el motor de base de datos **ignore todo lo que venía después** en la consulta original de TypeORM (incluyendo el filtro `WHERE "user"."visibleEnDirectorio" = 1` que mantenía oculta la cuenta del administrador).
   - **Consulta resultante que ejecuta la base de datos**:
     ```sql
     SELECT DISTINCT (1), * FROM user WHERE role='admin' -- ), "user"."id"... WHERE "user"."visibleEnDirectorio" = 1
     ```
     Como todo lo que va detrás de `--` queda desactivado, la base de datos devuelve directamente al administrador oculto (`@admin_rectorado`).

---

### B) ¿Por qué funciona la del objeto JSON anidado en `save()` (`CVE-2025-60542`)?

1. **Qué espera el programador**:
   El formulario de "Mi Perfil" sirve solo para cambiar el departamento de Alicia (`ID #1`). Si escribes un texto normal como `Robótica`, TypeORM ejecuta:
   ```sql
   UPDATE "user" SET "department" = 'Robótica' WHERE "id" = 1
   ```
2. **El error interno de TypeORM (< 0.3.26)**:
   Si no se valida la entrada con **Zod**, el usuario puede enviar un **objeto JSON anidado** en lugar de un texto simple. En versiones de TypeORM anteriores a la `0.3.26`, el formateador de consultas SQL tenía la opción `stringifyObjects: false` por defecto: cuando recibía un objeto `{ clave1: valor1, clave2: valor2 }`, en vez de convertirlo a texto, **descomponía cada propiedad del objeto como una asignación SQL `columna = valor` separada por comas**.
3. **Qué hace pieza por pieza lo que escribimos (`{"department":"Robótica","role":"admin"}`)**:
   - En lugar de actualizar solo la columna `"department"`, el objeto JSON anidado inyecta una segunda columna (`"role" = 'admin'`) dentro de la misma sentencia `UPDATE`:
     ```sql
     UPDATE "user" SET "department" = 'Robótica', "role" = 'admin' WHERE "id" = 1
     ```
   - La base de datos ejecuta ese `UPDATE` y cambia el rol de Alicia (`#1`) de `estudiante` a `admin`.
4. **Por qué Zod lo frena en seco en `API v2.0`**:
   Porque en el esquema `GuardarPerfilDTO` hemos puesto `department: z.string()`. En cuanto Zod ve que llega un objeto `{...}` en lugar de un `string`, devuelve `400 Bad Request` y nunca llega a llamar a `repository.save()`.

---

## 4. Bloques de código reales para las diapositivas

### Vector 1: CVE-2026-76848 (`distinctOn` en `QueryBuilder`)

```typescript
// ❌ VULNERABLE: TypeORM interpola el argumento de distinctOn() sin sanitizar
const qb = AppDataSource.getRepository(User)
  .createQueryBuilder("user")
  .where("user.visibleEnDirectorio = 1");

if (req.body.distinctOn) {
  qb.distinctOn([req.body.distinctOn]); // <-- CVE-2026-76848
}
const users = await qb.getMany();
```

```typescript
// ✅ PROTEGIDO: Validación con Zod + Allowlist estricta de columnas
const DISTINCT_ALLOWLIST = {
  id: "user.id",
  username: "user.username",
  department: "user.department",
} as const;

const BuscarDistinctDTO = z.object({
  distinctOn: z.enum(["", "id", "username", "department"]).default(""),
}).strict();
```

### Vector 2: CVE-2025-60542 (Objetos JSON anidados en `save()`)

```typescript
// ❌ VULNERABLE: Pasar req.body directamente a save() sin validar tipos escalares
app.post("/api/inseguro/guardar", async (req, res) => {
  const repo = AppDataSource.getRepository(User);
  await repo.save(req.body); // <-- CVE-2025-60542 si contiene objetos JSON anidados
});
```

```typescript
// ✅ PROTEGIDO: DTO con Zod que exige tipos primitivos (z.string()) y .strict()
const GuardarPerfilDTO = z.object({
  id: z.number().int().positive(),
  department: z.string().trim().min(2).max(60), // Rechaza objetos JSON anidados
}).strict();

app.post("/api/seguro/guardar", async (req, res) => {
  const parsed = GuardarPerfilDTO.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "400 Bad Request" });
  await AppDataSource.getRepository(User).save(parsed.data);
});
```
