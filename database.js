import "dotenv/config";
import pkg from "pg";

const { Client } = pkg;

const client = new Client({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  host: "localhost",
  database: process.env.DB_NAME
});

client.connect();

client.end();
