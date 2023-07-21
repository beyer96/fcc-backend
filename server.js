import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";

const app = express();
const port = process.env.PORT || 3000;

// enable using json in body of request
app.use(express.json());

// Middleware
const authenticateToken = (req, res, next) => {
  // authHeader = 'Bearer ACCESS_TOKEN'
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  // Valid token
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // Invalid token - no access
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
};

const generateAccessToken = user => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
};

// Routes
app.get("/", authenticateToken, (req, res) => {
  res.send(req.user);
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.sendStatus(401);
  // Check in database for existing refresh token.
  // if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = generateAccessToken({ name: user });
    res.json({ accessToken });
  });
});

// Authenticate User
app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  res.json({ accessToken, refreshToken });
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
