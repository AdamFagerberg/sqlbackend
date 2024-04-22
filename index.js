import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import cors from "cors";

const app = express();
const port = 3002;

// middleware

app.use(bodyParser.json());
app.use(cors());

// connect to DB
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "root",
  database: "banksql",
  port: 8889,
});

// help function to make code look nicer
async function query(sql, params) {
  const [results] = await pool.execute(sql, params);
  return results;
}

// function to create token

function createRandomString() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 7; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// routes/endpoints

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  //kryptera lösenordet innan det hamnar i DB
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  try {
    const result = await query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword]
    );

    await query("INSERT INTO accounts (userId) VALUES (?)", [result.insertId]);

    res.status(201).send("User created");
  } catch (error) {
    console.error("Error creating user", error);
    res.status(500).send("Error creating user");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await query("SELECT * FROM users WHERE username = ?", [
    username,
  ]);

  const user = result[0];

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (passwordMatch) {
    const token = createRandomString();

    await query("INSERT INTO sessions (userId, token) VALUES (?,?)", [
      user.id,
      token,
    ]);

    res.json({ token: token });
  } else {
    res.status(401).send("invalid username or password");
  }
});

app.post("/me/account/deposit", async (req, res) => {
  const { token, amount } = req.body;

  const currentSession = await query("SELECT * FROM sessions WHERE token = ?", [
    token,
  ]);

  const userId = currentSession[0].userId;

  await query("SELECT * FROM accounts WHERE userId = ?", [userId]);

  await query("UPDATE accounts SET balance = balance + ? WHERE userId = ?", [
    amount,
    userId,
  ]);

  const newBalance = await query(
    "SELECT balance FROM accounts WHERE userId = ?",
    [userId]
  );

  res.status(200).send(newBalance);
});

app.post("/me/account/balance", async (req, res) => {
  const { token } = req.body;

  const currentSession = await query("SELECT * FROM sessions WHERE token = ?", [
    token,
  ]);

  const userId = currentSession[0].userId;

  const account = await query("SELECT * FROM accounts WHERE userId = ?", [
    userId,
  ]);

  const accountBalance = account[0].balance;

  res.status(200).send(accountBalance.toString());
});

app.listen(port, () => {
  console.log("Listening on port " + port);
});
