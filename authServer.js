import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";

import { encryptPassword, isValidToken } from "./helpers/auth.js"; 
import { 
  deleteRefreshToken,
  getRefreshTokenDuration,
  registerUser,
  saveRefreshToken,
  verifyUser
} from "./database.js";
import { FIVE_MINUTES } from "./helpers/constants.js";

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

const generateAccessToken = user => jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
const generateRefreshToken = user => jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const encryptedPassword = await encryptPassword(password);

    await registerUser(username, encryptedPassword);

    const accessToken = generateAccessToken({ username });
    const refreshToken = generateRefreshToken({ username });

    await saveRefreshToken(refreshToken);

    res.cookie("accessToken", accessToken, { secure: true, httpOnly: true, expires: new Date(Date.now() + 30 * 1000 ), sameSite: "none" });
    res.cookie("refreshToken", refreshToken, { secure: true, httpOnly: true, expires: new Date(Date.now() + FIVE_MINUTES), sameSite: "none" });
    res.status(200).json({ username });
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
    const refreshToken = generateRefreshToken({ username });

    await saveRefreshToken(refreshToken);
  
    res.cookie("accessToken", accessToken, { secure: true, httpOnly: true, expires: new Date(Date.now() + 30 * 1000 ), sameSite: "none" });
    res.cookie("refreshToken", refreshToken, { secure: true, httpOnly: true, expires: new Date(Date.now() + FIVE_MINUTES), sameSite: "none" });
    res.status(200).json({ username, message: "Successfully logged in!" });
  } catch (err) {
    res.sendStatus(401);
  }
});

app.delete("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(404).json({ error: "Refresh token not found in DB" });

    await deleteRefreshToken(refreshToken);
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.sendStatus(204);
  } catch (err) {
    res.status(400).json({ error: `Unable to logout: ${err.message}` });
  }
});

app.post("/token", async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) return res.sendStatus(401);

  // check if refreshToken is in DB and if it's valid -> 403 if not
  const tokenDuration = await getRefreshTokenDuration(refreshToken);
  if (!tokenDuration) return res.status(403).json({ error: "Refresh token is not stored in database" });
  if (!isValidToken(tokenDuration)) return res.status(403).json({ error: "Refresh token is no longer valid" });

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = generateAccessToken({ username: user.username });
    res.cookie("accessToken", accessToken, { secure: true, httpOnly: true, expires: new Date(Date.now() + 30 * 1000 ), sameSite: "none" });
    res.sendStatus(200);
  });
});

app.listen(port);
