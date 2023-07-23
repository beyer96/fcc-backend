import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();
const port = process.env.PORT || 3000;
const corsOptions = {
  origin: ["http://localhost:4000", "https://localhost:5173"],
  credentials: true
};

// enable using json in body of request
app.use(express.json());
app.use(cookieParser(false));
app.use(cors(corsOptions));

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
  res.status(200).json({ user: req.user });
});

app.get("/users", (req, res) => {
  
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
