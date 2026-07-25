// Biudzeto knygos / smalllabs-api backend serveris.
//
// SAUGUMO PRINCIPAI, kuriu laikomasi siame faile:
// 1. Slaptazodziai NIEKADA nesaugomi ir nesiunciami kaip tekstas - tik bcrypt "hash".
// 2. Visos SQL uzklausos naudoja parametrus ($1, $2...), ne string sudeliojima -
//    tai apsaugo nuo SQL injection atakų.
// 3. Prisijungimo tokenas laikomas httpOnly slapuke (cookie), NE localStorage -
//    tai apsaugo nuo XSS atakų (kenkejiskas JS negali jo perskaityti).
// 4. Klaidos pranesimai neatskleidzia, ar el. pastas egzistuoja (login metu) -
//    kad piktavalis negaletu "surinkti" registruotu vartotoju sarasa.
// 5. Visi slapti raktai (DB rysys, JWT paslaptis) ateina is Environment Variables,
//    niekada nerasomi i pati koda.
// 6. Helmet.js prideda saugumo HTTP antrastes (OWASP rekomendacija).
// 7. Rate limiting apsaugo nuo brute-force atakų prisijungimo/registracijos endpoint'uose.

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

app.use(helmet());

// CORS: leidziame uzklausas is BET KURIO *.smalllabs.lt poddomenio (ir paties smalllabs.lt),
// kad viena paskyra veiktu visose programelese. Kitos kilmes (originai) atmetamos.
function leidziamasOriginas(origin) {
  if (!origin) return false;
  return origin === "https://smalllabs.lt" || /^https:\/\/[a-z0-9-]+\.smalllabs\.lt$/.test(origin);
}
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (leidziamasOriginas(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json());
app.use(cookieParser());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const JWT_SECRET = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 12;

if (!JWT_SECRET) {
  console.error("KLAIDA: trūksta JWT_SECRET aplinkos kintamojo. Serveris nesileis.");
  process.exit(1);
}

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get("/", (req, res) => {
  res.json({ status: "ok", message: "smalllabs-api veikia." });
});

app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS dabartinis_laikas");
    res.json({
      server: "ok",
      database: "ok",
      dabartinis_laikas: result.rows[0].dabartinis_laikas,
    });
  } catch (err) {
    console.error("DB klaida:", err.message);
    res.status(500).json({ server: "ok", database: "klaida", klaida: err.message });
  }
});

// Apsauga nuo brute-force atakų: ne daugiau 10 bandymų per 15 min. is vieno IP.
const authLimiteris = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { klaida: "Per daug bandymų. Pabandykite vėliau." },
});

// --- REGISTRACIJA ---
app.post("/api/register", authLimiteris, async (req, res) => {
  const { email, password } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ klaida: "Neteisingas el. pašto formatas." });
  }
  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ klaida: "Slaptažodis turi būti bent 8 simbolių." });
  }

  try {
    const esamas = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (esamas.rows.length > 0) {
      return res.status(409).json({ klaida: "Šis el. paštas jau registruotas." });
    }

    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const isAdmin = process.env.ADMIN_EMAIL && email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();
    const result = await pool.query(
      "INSERT INTO users (email, password_hash, is_admin) VALUES ($1, $2, $3) RETURNING id, email, is_admin, created_at",
      [email, password_hash, !!isAdmin]
    );

    res.status(201).json({ vartotojas: result.rows[0] });
  } catch (err) {
    console.error("Registracijos klaida:", err.message);
    res.status(500).json({ klaida: "Nepavyko sukurti paskyros. Bandykite dar kartą." });
  }
});

// --- PRISIJUNGIMAS ---
app.post("/api/login", authLimiteris, async (req, res) => {
  const { email, password } = req.body;

  if (!isValidEmail(email) || typeof password !== "string") {
    return res.status(400).json({ klaida: "Neteisingas el. paštas arba slaptažodis." });
  }

  try {
    const result = await pool.query("SELECT id, email, password_hash FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ klaida: "Neteisingas el. paštas arba slaptažodis." });
    }

    const vartotojas = result.rows[0];
    const slaptazodisTeisingas = await bcrypt.compare(password, vartotojas.password_hash);
    if (!slaptazodisTeisingas) {
      return res.status(401).json({ klaida: "Neteisingas el. paštas arba slaptažodis." });
    }

    const token = jwt.sign({ userId: vartotojas.id }, JWT_SECRET, { expiresIn: "7d" });

    res.cookie("session", token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      domain: ".smalllabs.lt",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ vartotojas: { id: vartotojas.id, email: vartotojas.email } });
  } catch (err) {
    console.error("Prisijungimo klaida:", err.message);
    res.status(500).json({ klaida: "Nepavyko prisijungti. Bandykite dar kartą." });
  }
});

function reikalingasPrisijungimas(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    return res.status(401).json({ klaida: "Reikia prisijungti." });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ klaida: "Prisijungimo sesija nebegalioja." });
  }
}

app.get("/api/me", reikalingasPrisijungimas, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, email, is_admin, created_at FROM users WHERE id = $1", [req.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ klaida: "Vartotojas nerastas." });
    }
    res.json({ vartotojas: result.rows[0] });
  } catch (err) {
    console.error("Klaida /api/me:", err.message);
    res.status(500).json({ klaida: "Serverio klaida." });
  }
});

// --- PASKYROS ISTRYNIMAS (GDPR) ---
// Reikalauja slaptazodzio patvirtinimo saugumui - kad nepakaktu vien pavogto slapuko
// istrinti visa paskyra. Istrinus useri, app_data eilutes issitrina automatiskai
// (ON DELETE CASCADE), nes taip apibrezta lenteleje.
app.delete("/api/account", reikalingasPrisijungimas, async (req, res) => {
  const { password } = req.body;
  if (typeof password !== "string") {
    return res.status(400).json({ klaida: "Reikia patvirtinti slaptažodžiu." });
  }
  try {
    const vartotojas = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.userId]);
    if (vartotojas.rows.length === 0) {
      return res.status(404).json({ klaida: "Vartotojas nerastas." });
    }
    const teisingas = await bcrypt.compare(password, vartotojas.rows[0].password_hash);
    if (!teisingas) {
      return res.status(401).json({ klaida: "Neteisingas slaptažodis." });
    }
    await pool.query("DELETE FROM users WHERE id = $1", [req.userId]);
    res.clearCookie("session", { domain: ".smalllabs.lt" });
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Klaida /api/account (DELETE):", err.message);
    res.status(500).json({ klaida: "Nepavyko ištrinti paskyros. Jei esi šeimos kūrėjas, pirma reikia perleisti ar ištrinti šeimą." });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session", { domain: ".smalllabs.lt" });
  res.json({ status: "ok" });
});

// --- DUOMENU SINCHRONIZACIJA ---
// Paprastas atvejis: grazina prisijungusio vartotojo duomenis.
// Family Pack atvejis: jei "parent" prideda ?vartotojo_id=X ir X yra tos pacios seimos
// narys, gauna TO nario duomenis (tik skaitymui, per si endpoint'a). Vaikai (child)
// visada gauna tik savo duomenis, nesvarbu, ka iraso i ?vartotojo_id=.
app.get("/api/data", reikalingasPrisijungimas, async (req, res) => {
  try {
    let tikslinisId = req.userId;
    const prasomasId = req.query.vartotojo_id ? parseInt(req.query.vartotojo_id, 10) : null;

    if (prasomasId && prasomasId !== req.userId) {
      const manoDuomenys = await pool.query("SELECT family_id, role FROM users WHERE id = $1", [req.userId]);
      const galiuZiuretiKitus = manoDuomenys.rows[0] && manoDuomenys.rows[0].role === "parent";
      if (!galiuZiuretiKitus) {
        return res.status(403).json({ klaida: "Neturi teisės matyti kito vartotojo duomenų." });
      }
      const tikslinisVartotojas = await pool.query("SELECT family_id FROM users WHERE id = $1", [prasomasId]);
      const taPatiSeima =
        tikslinisVartotojas.rows[0] &&
        tikslinisVartotojas.rows[0].family_id === manoDuomenys.rows[0].family_id;
      if (!taPatiSeima) {
        return res.status(403).json({ klaida: "Šis vartotojas nepriklauso tavo šeimai." });
      }
      tikslinisId = prasomasId;
    }

    const result = await pool.query("SELECT key, value FROM app_data WHERE user_id = $1", [tikslinisId]);
    const duomenys = {};
    for (const eilute of result.rows) {
      duomenys[eilute.key] = eilute.value;
    }
    res.json(duomenys);
  } catch (err) {
    console.error("Klaida /api/data (GET):", err.message);
    res.status(500).json({ klaida: "Nepavyko gauti duomenų." });
  }
});
// Sugeneruoja atsitiktini, lengvai perskaitoma kvietimo koda (pvz. "ABC123").
function sugeneruotiKvietimoKoda() {
  const raidesSkaiciai = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // be O/0/I/1, kad nesipainiotu
  let kodas = "";
  for (let i = 0; i < 6; i++) {
    kodas += raidesSkaiciai[Math.floor(Math.random() * raidesSkaiciai.length)];
  }
  return kodas;
}

// Sukurti nauja seima. Prisijunges vartotojas tampa "parent" ir jos kurejas.
app.post("/api/family/create", reikalingasPrisijungimas, async (req, res) => {
  const { name } = req.body;
  if (typeof name !== "string" || name.trim().length === 0) {
    return res.status(400).json({ klaida: "Reikia šeimos pavadinimo." });
  }
  try {
    const kvietimoKodas = sugeneruotiKvietimoKoda();
    const seima = await pool.query(
      "INSERT INTO families (name, invite_code, created_by) VALUES ($1, $2, $3) RETURNING id, name, invite_code",
      [name.trim(), kvietimoKodas, req.userId]
    );
    await pool.query("UPDATE users SET family_id = $1, role = 'parent' WHERE id = $2", [
      seima.rows[0].id,
      req.userId,
    ]);
    res.status(201).json({ seima: seima.rows[0] });
  } catch (err) {
    console.error("Klaida /api/family/create:", err.message);
    res.status(500).json({ klaida: "Nepavyko sukurti šeimos." });
  }
});

// Prisijungti prie esamos seimos per kvietimo koda. Prisijungiantis visada tampa "child".
app.post("/api/family/join", reikalingasPrisijungimas, async (req, res) => {
  const { invite_code } = req.body;
  if (typeof invite_code !== "string" || invite_code.trim().length === 0) {
    return res.status(400).json({ klaida: "Reikia kvietimo kodo." });
  }
  try {
    const seima = await pool.query("SELECT id, name FROM families WHERE invite_code = $1", [
      invite_code.trim().toUpperCase(),
    ]);
    if (seima.rows.length === 0) {
      return res.status(404).json({ klaida: "Toks kvietimo kodas nerastas." });
    }
    await pool.query("UPDATE users SET family_id = $1, role = 'child' WHERE id = $2", [
      seima.rows[0].id,
      req.userId,
    ]);
    res.json({ seima: seima.rows[0] });
  } catch (err) {
    console.error("Klaida /api/family/join:", err.message);
    res.status(500).json({ klaida: "Nepavyko prisijungti prie šeimos." });
  }
});

// Grazina seimos info ir jos nariu sarasa (matoma visiems seimos nariams).
app.get("/api/family", reikalingasPrisijungimas, async (req, res) => {
  try {
    const vartotojas = await pool.query("SELECT family_id, role FROM users WHERE id = $1", [req.userId]);
    if (!vartotojas.rows[0] || !vartotojas.rows[0].family_id) {
      return res.status(404).json({ klaida: "Nepriklausai jokiai šeimai." });
    }
    const familyId = vartotojas.rows[0].family_id;
    const seima = await pool.query("SELECT id, name, invite_code FROM families WHERE id = $1", [familyId]);
    const nariai = await pool.query(
      "SELECT id, email, role, created_at FROM users WHERE family_id = $1 ORDER BY role DESC, created_at ASC",
      [familyId]
    );
    res.json({ seima: seima.rows[0], nariai: nariai.rows, mano_role: vartotojas.rows[0].role });
  } catch (err) {
    console.error("Klaida /api/family:", err.message);
    res.status(500).json({ klaida: "Nepavyko gauti šeimos informacijos." });
  }
});



// Tevas/mama gali pakeisti kito seimos nario role (parent/child).
// Savo paties roles per si endpoint'a pakeisti negalima (kad seima netyciom
// neliktu be neivieno "parent" nario).
app.patch("/api/family/member/:id/role", reikalingasPrisijungimas, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { role } = req.body;
  if (role !== "parent" && role !== "child") {
    return res.status(400).json({ klaida: "Role turi būti 'parent' arba 'child'." });
  }
  if (targetId === req.userId) {
    return res.status(400).json({ klaida: "Negali pakeisti savo pačio rolės." });
  }
  try {
    const manoDuomenys = await pool.query("SELECT family_id, role FROM users WHERE id = $1", [req.userId]);
    if (!manoDuomenys.rows[0] || manoDuomenys.rows[0].role !== "parent") {
      return res.status(403).json({ klaida: "Tik tėvas/mama gali keisti narių roles." });
    }
    const tikslinisVartotojas = await pool.query("SELECT family_id FROM users WHERE id = $1", [targetId]);
    if (!tikslinisVartotojas.rows[0] || tikslinisVartotojas.rows[0].family_id !== manoDuomenys.rows[0].family_id) {
      return res.status(403).json({ klaida: "Šis vartotojas nepriklauso tavo šeimai." });
    }
    await pool.query("UPDATE users SET role = $1 WHERE id = $2", [role, targetId]);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Klaida /api/family/member/:id/role:", err.message);
    res.status(500).json({ klaida: "Nepavyko pakeisti rolės." });
  }
});

app.put("/api/data/:key", reikalingasPrisijungimas, async (req, res) => {
  const { key } = req.params;
  const { value } = req.body;
  if (value === undefined) {
    return res.status(400).json({ klaida: "Trūksta 'value' lauko." });
  }
  try {
    await pool.query(
      `INSERT INTO app_data (user_id, key, value, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, key)
       DO UPDATE SET value = $3, updated_at = NOW()`,
      [req.userId, key, JSON.stringify(value)]
    );
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Klaida /api/data/:key (PUT):", err.message);
    res.status(500).json({ klaida: "Nepavyko išsaugoti." });
  }
});

app.post("/api/data/bulk-import", reikalingasPrisijungimas, async (req, res) => {
  const visiDuomenys = req.body;
  if (typeof visiDuomenys !== "object" || Array.isArray(visiDuomenys)) {
    return res.status(400).json({ klaida: "Neteisingas duomenų formatas." });
  }
  try {
    const raktai = Object.keys(visiDuomenys);
    for (const key of raktai) {
      await pool.query(
        `INSERT INTO app_data (user_id, key, value, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (user_id, key)
         DO UPDATE SET value = $3, updated_at = NOW()`,
        [req.userId, key, JSON.stringify(visiDuomenys[key])]
      );
    }
    res.json({ status: "ok", perkelta: raktai.length });
  } catch (err) {
    console.error("Klaida /api/data/bulk-import:", err.message);
    res.status(500).json({ klaida: "Nepavyko perkelti duomenų." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveris veikia ant prievado ${PORT}`);
});
