import { URL } from "node:url";
import { charts, connect, isReady, mapChart, toId, users } from "./db.js";
import { createApp, readJson, sendEmpty, sendJson, serveStatic } from "./http.js";
import { getUserFromRequest, hashPassword, signToken, verifyPassword } from "./middleware/auth.js";

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const SIGNS = [
  ["01-20", "Capricornio"], ["02-19", "Acuario"], ["03-21", "Piscis"], ["04-20", "Aries"],
  ["05-21", "Tauro"], ["06-21", "Geminis"], ["07-23", "Cancer"], ["08-23", "Leo"],
  ["09-23", "Virgo"], ["10-23", "Libra"], ["11-22", "Escorpio"], ["12-22", "Sagitario"]
];
function usernameQuery(username) { return new RegExp("^" + username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$", "i"); }
function requireUser(req, res) { const user = getUserFromRequest(req); if (!user) { sendJson(res, 401, { error: "No autenticado" }); return null; } return user; }
function signOf(day) {
  const md = String(day).slice(5);
  let current = "Capricornio";
  for (const [start, name] of SIGNS) if (md >= start) current = name;
  return current;
}

const server = createApp(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const { pathname } = url;
  const method = req.method || "GET";
  if (pathname === "/health") return sendJson(res, 200, { ok: true, db: isReady() });
  if (pathname.startsWith("/api/") && !isReady()) return sendJson(res, 503, { error: "Base no lista" });
  if (!pathname.startsWith("/api/")) return serveStatic(req, res);

  if (method === "POST" && pathname === "/api/auth/register") {
    const body = await readJson(req);
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    if (!USERNAME_RE.test(username)) return sendJson(res, 400, { error: "Usuario: 3-20 caracteres, letras, numeros y _" });
    if (password.length < 6) return sendJson(res, 400, { error: "La contrasena debe tener al menos 6 caracteres" });
    if (await users().findOne({ username: usernameQuery(username) })) return sendJson(res, 409, { error: "Ese usuario ya existe" });
    const result = await users().insertOne({ username, passwordHash: hashPassword(password), createdAt: new Date() });
    const user = { id: String(result.insertedId), username };
    return sendJson(res, 201, { user, token: signToken(user) });
  }
  if (method === "POST" && pathname === "/api/auth/login") {
    const body = await readJson(req);
    const username = String(body.username || "").trim();
    const row = await users().findOne({ username: usernameQuery(username) });
    if (!row || !verifyPassword(String(body.password || ""), row.passwordHash)) return sendJson(res, 401, { error: "Usuario o contrasena incorrectos" });
    const user = { id: String(row._id), username: row.username };
    return sendJson(res, 200, { user, token: signToken(user) });
  }
  if (method === "GET" && pathname === "/api/auth/me") {
    const user = requireUser(req, res);
    if (!user) return;
    return sendJson(res, 200, { user });
  }

  const user = requireUser(req, res);
  if (!user) return;
  const userId = user.id;

  if (method === "GET" && pathname === "/api/charts") {
    const rows = await charts().find({ userId }).sort({ day: -1 }).limit(50).toArray();
    return sendJson(res, 200, { charts: rows.map(mapChart) });
  }
  if (method === "POST" && pathname === "/api/charts") {
    const body = await readJson(req);
    const name = String(body.name || "").trim();
    if (!name || !/^\d{4}-\d{2}-\d{2}$/.test(body.day)) return sendJson(res, 400, { error: "Nombre y fecha son obligatorios" });
    const result = await charts().insertOne({ userId, name: name.slice(0, 40), day: body.day, time: /^\d{2}:\d{2}$/.test(body.time) ? body.time : "", place: String(body.place || "").slice(0, 60), notes: String(body.notes || "").slice(0, 400), sign: signOf(body.day), createdAt: new Date() });
    return sendJson(res, 201, { chart: mapChart(await charts().findOne({ _id: result.insertedId })) });
  }
  const match = pathname.match(/^\/api\/charts\/([a-fA-F0-9]{24})$/);
  if (match && method === "DELETE") {
    const result = await charts().deleteOne({ _id: toId(match[1]), userId });
    if (!result.deletedCount) return sendJson(res, 404, { error: "Carta no encontrada" });
    return sendEmpty(res, 204);
  }
  sendJson(res, 404, { error: "Ruta no encontrada" });
});

server.listen(PORT, HOST, () => console.log(`Natal en http://${HOST}:${PORT}`));
async function bootDb() { for (;;) { try { await connect(); return; } catch (err) { console.error("Mongo no disponible:", err.message); await new Promise((resolve) => setTimeout(resolve, 5000)); } } }
bootDb();
