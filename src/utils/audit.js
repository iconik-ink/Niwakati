// `db` can be the pool or a transaction client; both expose .query()
export async function audit(db, { actorId = null, action, targetId = null, meta = {}, ip = null }) {
  await db.query(
    `INSERT INTO audit_logs (actor_id, action, target_id, meta, ip) VALUES ($1,$2,$3,$4,$5)`,
    [actorId, action, targetId, JSON.stringify(meta), ip]
  );
}
