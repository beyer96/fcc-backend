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

// Routes
app.get("/", authenticateToken, (req, res) => {
  res.send(req.user);
});

app.get("/users", (req, res) => {
  
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
