import express from "express";
import "dotenv/config";

const app = express();
const port = process.env.PORT || 3000;

// Routes
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
