import { DataSource } from "typeorm";
import { User } from "../entities/User";

/**
 * Fuente de datos de la demo: SQLite EN MEMORIA.
 *
 * Elegimos SQLite para que el proyecto arranque con un simple `npm start`, sin
 * depender de un servidor de base de datos externo (ideal para una demo en vivo).
 *
 * - `synchronize: true`  -> TypeORM crea el esquema a partir de la entidad al arrancar.
 * - `logging: true`      -> imprime en la terminal CADA consulta SQL que ejecuta.
 *                           Ese log es la prueba visual de las inyecciones.
 *
 * Al reiniciar el proceso, la base vuelve al estado inicial (ver db/seed.ts).
 */
export const AppDataSource = new DataSource({
  type: "sqlite",
  database: ":memory:",
  entities: [User],
  synchronize: true,
  logging: true,
});
