import { AppDataSource } from "./data-source";
import { User } from "../entities/User";

/**
 * Datos de prueba iniciales. Se cargan al arrancar y, como la base es en memoria,
 * se regeneran limpios en cada reinicio del proceso.
 *
 * `admin_rectorado` tiene `visibleEnDirectorio: false`: es la cuenta OCULTA que el
 * ataque CVE-2026-76848 logrará revelar.
 */
export async function cargarDatosDePrueba(): Promise<void> {
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
}
