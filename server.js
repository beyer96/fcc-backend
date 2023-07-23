import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import CookieParser from "cookie-parser";

const app = express();
const port = process.env.PORT || 3000;

// enable using json in body of request
app.use(express.json());
app.use(CookieParser());

// Middleware
const authenticateToken = (req, res, next) => {
  const { accessToken } = req.cookies;
  if (!accessToken) return res.sendStatus(401);

  // Valid token
  jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // Invalid token - no access
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
};

// Routes
app.get("/", authenticateToken, (req, res) => {
  res.send(req.user);
});

app.get("/users", (req, res) => {
  
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
