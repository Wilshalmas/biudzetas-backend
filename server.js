// Biudžeto knygos backend serveris — pradinis karkasas.
// Šis failas tikrina, ar serveris veikia ir ar jis gali pasiekti duomenų bazę.

const express = require("express");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

// SVARBU: connection string ateina iš aplinkos kintamojo (Environment Variable),
// niekada nerašomas tiesiai į kodą. Coolify'yje jį nustatysime atskirai.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Paprastas "gyvybės" patikrinimas — ar pats serveris veikia.
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Biudžeto knygos backend veikia." });
});

// Patikrinimas, ar serveris gali pasiekti duomenų bazę.
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
    res.status(500).json({
      server: "ok",
      database: "klaida",
      klaida: err.message,
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveris veikia ant prievado ${PORT}`);
});
