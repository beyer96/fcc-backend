import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";

import { encryptPassword } from "./helpers/auth.js"; 
import { registerUser, verifyUser, getUser } from "./database.js";
import { DAY, FIVE_MINUTES } from "./helpers/constants.js";

const app = express();
const port = process.env.AUTH_SERVER_PORT || 4000;
const allowedOrigins = ["http://localhost:3000", "http://localhost:5173"];
const corsOptions = {
  origin: allowedOrigins,
  credentials: true
};

// Middlewares
const credentials = (req, res, next) => {
  const { origin } = req.headers;
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Credentials", true);
  }
  next();
};

app.use(express.json());
app.use(cookieParser());
app.use(credentials);
app.use(cors(corsOptions));

const generateAccessToken = user => jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: FIVE_MINUTES });
const generateRefreshToken = user => jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: DAY });

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const encryptedPassword = await encryptPassword(password);
    const user = await registerUser(username, encryptedPassword);
    const accessToken = generateAccessToken({ username });
    const refreshToken = generateRefreshToken({ username });

    res.cookie("accessToken", accessToken, { secure: true, httpOnly: true, maxAge: FIVE_MINUTES, sameSite: "none" });
    res.cookie("refreshToken", refreshToken, { secure: true, httpOnly: true, maxAge: DAY, sameSite: "none" });
    res.cookie("fcc-session", true, { maxAge: DAY });
    res.status(200).json({ 
      user: {
        username: user.username,
        createdAt: user.created_at,
        cardIds: user.card_ids
      },
      accessTokenExpiration: Date.now() + FIVE_MINUTES
    });
  } catch (err) {
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await verifyUser(username, password);
    if (!user) return res.sendStatus(401);

    const accessToken = generateAccessToken({ username: user.username });
    const refreshToken = generateRefreshToken({ username: user.username });
  
    res.cookie("accessToken", accessToken, { secure: true, httpOnly: true, maxAge: FIVE_MINUTES, sameSite: "none" });
    res.cookie("refreshToken", refreshToken, { secure: true, httpOnly: true, maxAge: DAY, sameSite: "none" });
    res.cookie("fcc-session", true, { maxAge: DAY });
    res.status(200).json({
      user: {
        username: user.username,
        createdAt: user.created_at,
        cardIds: user.card_ids
      },
      accessTokenExpiration: Date.now() + FIVE_MINUTES
    });
  } catch (err) {
    res.sendStatus(401);
  }
});

app.get("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.sendStatus(204);

    res.clearCookie("accessToken", { secure: true, httpOnly: true, sameSite: "none" });
    res.clearCookie("refreshToken", { secure: true, httpOnly: true, sameSite: "none" });
    res.clearCookie("fcc-session");
    res.sendStatus(204);
  } catch (err) {
    res.status(400).json({ error: `Unable to logout: ${err.message}` });
  }
});

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = generateAccessToken({ username: user.username });
    const refreshToken = generateRefreshToken({ username: user.username });

    const userFromDb = await getUser(user.username);

    res.cookie("accessToken", accessToken, { secure: true, httpOnly: true, maxAge: FIVE_MINUTES, sameSite: "none" });
    res.cookie("refreshToken", refreshToken, { secure: true, httpOnly: true, maxAge: DAY, sameSite: "none" });
    res.cookie("fcc-session", true, { maxAge: DAY });
    res.status(200).json({ 
      user: {
        username: userFromDb.username,
        createdAt: userFromDb.created_at,
        cardIds: userFromDb.card_ids
      },
      accessTokenExpiration: Date.now() + FIVE_MINUTES
    });
  });
});

app.listen(port);
