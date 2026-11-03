import { Entity, PrimaryGeneratedColumn, Column } from "typeorm";

/**
 * Entidad `User` -> tabla `user`.
 *
 * Representa a un miembro del campus. Dos de sus campos son el OBJETIVO de los
 * ataques de esta demo:
 *   - `role`                 -> el CVE-2025-60542 lo usa para escalar a "admin".
 *   - `visibleEnDirectorio`  -> el CVE-2026-76848 lo usa para revelar cuentas ocultas.
 */
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
