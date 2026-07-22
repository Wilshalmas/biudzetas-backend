// Biudzeto knygos backend serveris.
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

const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(cookieParser());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const JWT_SECRET = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 12; // kiek kartu maisomas slaptazodis - kuo daugiau, tuo saugiau, bet leciau

if (!JWT_SECRET) {
  console.error("KLAIDA: trūksta JWT_SECRET aplinkos kintamojo. Serveris nesileis.");
  process.exit(1);
}

// --- Pagalbine funkcija: paprastas el. pasto formato patikrinimas ---
function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Biudžeto knygos backend veikia." });
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

// --- REGISTRACIJA ---
app.post("/api/register", async (req, res) => {
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
    // Jei registruojamasi su ADMIN_EMAIL nurodytu el. pastu, paskyra automatiskai
    // gauna pilna (is_admin) prieiga - be prenumeratos, be mokejimo.
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
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!isValidEmail(email) || typeof password !== "string") {
    // Tyciotai neaiskus pranesimas - nesakome, ar problema el. pastas, ar slaptazodis.
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
      httpOnly: true, // kenkejiskas JS naršykleje negali perskaityti sio slapuko
      secure: true, // siunciamas tik per HTTPS
      sameSite: "strict", // apsauga nuo CSRF atakų
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dienos
    });

    res.json({ vartotojas: { id: vartotojas.id, email: vartotojas.email } });
  } catch (err) {
    console.error("Prisijungimo klaida:", err.message);
    res.status(500).json({ klaida: "Nepavyko prisijungti. Bandykite dar kartą." });
  }
});

// --- Pagalbine funkcija: patikrina, ar uzklausa ateina nuo prisijungusio vartotojo ---
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

// --- Testinis apsaugotas endpoint'as - patikrinti, ar prisijungimas veikia ---
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

// --- ATSIJUNGIMAS ---
app.post("/api/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ status: "ok" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveris veikia ant prievado ${PORT}`);
});
