import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";

import { encryptPassword } from "./helpers.js"; 
import { registerUser, verifyUser } from "./database.js";

const app = express();
const port = process.env.AUTH_SERVER_PORT || 4000;

app.use(express.json());

const generateAccessToken = user => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
};

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const encryptedPassword = await encryptPassword(password);

    await registerUser(username, encryptedPassword);

    const accessToken = generateAccessToken({ username });
    const refreshToken = jwt.sign({ username }, process.env.REFRESH_TOKEN_SECRET);

    res.status(200).json({ username, accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
  
    const validLogin = await verifyUser(username, password);
    if (!validLogin) return res.sendStatus(401);

    const accessToken = generateAccessToken({ username });
    const refreshToken = jwt.sign({ username }, process.env.REFRESH_TOKEN_SECRET);
  
    res.send({ username, accessToken, refreshToken });
  } catch (err) {
    res.sendStatus(401);
  }
});

app.post("/token", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.sendStatus(401);

  // check if refreshToken is in DB -> 403 if not

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = generateAccessToken({ username: user.username });
    res.json({ accessToken });
  });
});

app.listen(port);
