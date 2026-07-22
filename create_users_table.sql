-- Vartotoju lentele. Slaptazodis NIEKADA nesaugomas kaip tekstas -
-- saugomas tik jo "hash" (vienpusis uzsifravimas, kurio negalima atsukti atgal).
-- is_admin = true reiskia pilna prieiga be prenumeratos (skirta savininkui).
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
