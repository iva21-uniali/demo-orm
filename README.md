# El mito de que los ORMs impiden la Inyección SQL — Demo (TypeORM)

> **Tesis:** usar un ORM (TypeORM) **no** te hace inmune a la inyección SQL. El ORM
> parametriza los *valores* normales, pero se rompe cuando la entrada del usuario
> entra por un hueco que no se puede parametrizar o con una *forma* inesperada. La
> defensa real es **validar la entrada** (lista blanca + tipos) antes del ORM.

Proyecto educativo en local (`Node.js + Express + TypeScript + TypeORM + SQLite en memoria`)
que reproduce en vivo dos vulnerabilidades reales de TypeORM:

| CVE | Dónde | Efecto en la demo |
|-----|-------|-------------------|
| **CVE-2026-76848** | `SelectQueryBuilder.distinctOn()` | Revela una cuenta de administrador oculta |
| **CVE-2025-60542** | objeto JSON anidado en `repository.save()` | Escala a `alice` de `estudiante` a `admin` |

Además se muestran dos fallos de diseño asociados como **defensa en profundidad**:
*mass assignment* (volcar `req.body` entero) e **IDOR** (confiar en el `id` del cuerpo).

---

## 1. Arranque

### Opción A — Node.js local
```bash
npm install
npm start
```

### Opción B — Docker
```bash
docker compose up --build
```
*(Para reiniciar la base en memoria: `Ctrl + C` y volver a arrancar.)*

- Interfaz web: **http://localhost:3000** (ponla a la izquierda).
- Terminal a la derecha: con `logging: true`, TypeORM imprime **cada SQL** que ejecuta.
  Ese log es la prueba visual de las inyecciones.

El botón arriba a la derecha alterna la API:
- **🟠 API v1.0** = endpoints vulnerables (`/api/vulnerable/...`).
- **🟢 API v2.0** = endpoints protegidos con Zod + lista blanca (`/api/seguro/...`).

---

## 2. Honestidad del montaje (léelo antes de la defensa)

Los dos CVE son **reales y publicados**, pero cada uno solo se dispara de forma
**nativa** sobre un motor concreto:

- **CVE-2026-76848** → nativo solo en **PostgreSQL**.
- **CVE-2025-60542** → nativo solo en **MySQL/mysql2** con **TypeORM < 0.3.26**.

Esta demo usa **SQLite en memoria** para arrancar sin servidores externos. Por eso,
para verlos aquí, hay que *traer* el comportamiento vulnerable a SQLite. Toda esa
"fontanería" está aislada y documentada en **[`src/db/reproduction.ts`](src/db/reproduction.ts)**:

- **CVE-2026-76848:** se sobreescribe `createSelectDistinctExpression` para que emita
  la interpolación insegura también en SQLite. La lógica (`replacePropertyNames` **sin
  lista blanca**) es **idéntica** a la de TypeORM; lo único que se quita es el candado
  `if (isPostgresFamily)` que la limita a Postgres.
- **CVE-2025-60542:** se usa la **librería real `sqlstring`** (la que causa el CVE) con
  `stringifyObjects: false` para expandir el objeto anidado en columnas, y se ejecuta
  sobre SQLite (que acepta identificadores con *backticks*). El driver nativo de SQLite
  no pasa por `sqlstring`, por eso hay que invocarla explícitamente.

**Frase para el tribunal:** *"La lógica vulnerable es la de la librería real; lo único
artificial es ejecutarla sobre SQLite en vez del motor donde el bug está activo por
defecto."*

> Nota de versión: en producción, el CVE-2025-60542 se corrige **actualizando a TypeORM
> ≥ 0.3.26**; el CVE-2026-76848 afecta hasta la 1.1.0. La defensa por validación de
> entrada protege en cualquier versión.

---

## 3. Estructura del código

```
src/
├─ index.ts                 Arranque: habilita reproducción, inicializa DB, levanta server
├─ app.ts                   Construye Express y monta las rutas
├─ entities/User.ts         Entidad User -> tabla "user"
├─ db/
│  ├─ data-source.ts        Conexión SQLite en memoria (logging activado)
│  ├─ seed.ts               Datos de prueba (incluye la cuenta admin oculta)
│  └─ reproduction.ts       ⭐ Reproducción didáctica de los dos CVE (ver sección 2)
├─ validation/schemas.ts    DTOs de Zod + lista blanca (la defensa)
├─ security/session.ts      Sesión simulada (defensa IDOR)
└─ routes/
   ├─ vulnerable.ts         API v1.0 — endpoints sin validar
   └─ secure.ts             API v2.0 — endpoints con Zod + lista blanca + sesión
public/                     Interfaz web (index.html, styles.css, app.js)
```

---

## 4. Guion de pruebas en vivo

### Vector A — CVE-2026-76848 (`distinctOn`)
Buscador de la derecha (*"Agrupar vista por campo..."*):

1. **Normal (🟠):** escribe `department` → agrupa por departamento, SQL:
   `SELECT DISTINCT (department), ...`
2. **Ataque (🟠):** escribe `1), * FROM user WHERE role='admin' --` → aparece la cuenta
   oculta **`@admin_rectorado`**. El `1)` cierra el paréntesis, inyecta una consulta nueva
   y `--` comenta el filtro `visibleEnDirectorio = 1`.
3. **Remediado (🟢):** el mismo payload → **HTTP 400** (lista blanca: `id`, `username`, `department`).

### Vector B — CVE-2025-60542 (objeto anidado en `save()`)
Campo *"Departamento / Especialidad"* de *"Mi Perfil"*:

1. **Normal (🟠):** escribe `Robótica` → `UPDATE "user" SET "department" = ? ...`, `alice`
   sigue siendo `estudiante`.
2. **Ataque (🟠):** escribe `{"department":"Robótica","role":"admin"}` → `sqlstring`
   expande el objeto a `` SET `department` = 'Robotica', `role` = 'admin' `` y **`alice`
   pasa a `admin`** (fila roja).
3. **Remediado (🟢):** el mismo payload → **HTTP 400** (`department` debe ser `string`).

### Defensa en profundidad (demostrable por `curl`)
```bash
# Mass assignment (vulnerable): sin objeto anidado, bob escala a admin
curl -X POST localhost:3000/api/vulnerable/perfil \
  -H 'Content-Type: application/json' -d '{"id":2,"role":"admin"}'

# En el endpoint seguro: .strict() rechaza claves extra (role) y el id del cuerpo (IDOR)
curl -X POST localhost:3000/api/seguro/perfil \
  -H 'Content-Type: application/json' -d '{"id":2,"role":"admin","department":"x"}'
# -> 400: Unrecognized key(s) in object: 'id', 'role'
```
El endpoint seguro **no acepta `id`**: el usuario a modificar se toma de la **sesión
autenticada** (`src/security/session.ts`), nunca del cuerpo de la petición.

---

## 5. Las tres capas de la defensa (API v2.0)

| Amenaza | Defensa | Dónde |
|---------|---------|-------|
| CVE-2026-76848 (distinctOn) | `z.enum([...])` + lista blanca de columnas | [`validation/schemas.ts`](src/validation/schemas.ts) |
| CVE-2025-60542 (objeto anidado) | `department: z.string()` rechaza objetos | [`validation/schemas.ts`](src/validation/schemas.ts) |
| Mass assignment | `.strict()` + `update()` con columnas explícitas | [`routes/secure.ts`](src/routes/secure.ts) |
| IDOR | `id` tomado de la sesión, no del `req.body` | [`security/session.ts`](src/security/session.ts) |

**Conclusión:** el ORM protege el camino feliz, pero la validación de entrada y el control
de autorización son responsabilidad del desarrollador. Un ORM no es un sustituto de la
validación.

---

## 6. Comprobación de tipos
```bash
npm run typecheck   # tsc --noEmit, debe salir sin errores
```
