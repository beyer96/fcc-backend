import "dotenv/config";
import pkg from "pg";
import bcrypt from "bcrypt";
import { FIVE_MINUTES } from "./helpers/constants.js";

const { Client } = pkg;

const clientConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  host: "localhost",
  database: process.env.DB_NAME
};

export const getUsers = () => {
  const client = new Client(clientConfig);

  client.connect();
  client.query(`
    SELECT username from users;
  `);
};

export const registerUser = async (username, password) => {
  const client = new Client(clientConfig);

  try {
    await client.connect();

    const queryText = `
      INSERT INTO users (
        username,
        password,
        card_ids,
        created_at
      )
      VALUES (
        $1,
        $2,
        ARRAY[]::int[],
        CURRENT_TIMESTAMP
      ) ON CONFLICT (username) DO NOTHING;
    `;
    const values = [username, password];
    const result = await client.query(queryText, values);

    if (result.rowCount > 0) {
      console.log(`User ${username} successfully created!`);
    } else {
      console.log(`User ${username} already exists!`);
    }
  } catch (err) {
    console.log(`User ${username} could not be saved to the database: ${err.message}`);
  } finally {
    client.end();
  }
};

export const verifyUser = async (username, password) => {
  const client = new Client(clientConfig);

  try {
    const queryText = `SELECT * FROM users WHERE username = $1;`;

    await client.connect();
    const user = await client.query(queryText, [username]);
    if (user.rowCount == 0) return false;

    const hashedPassword = user.rows[0].password;
    const isPasswordValid = await bcrypt.compare(password, hashedPassword);

    return isPasswordValid;
  } catch (err) {
    console.log(err.message);
  } finally {
    client.end();
  }
};

export const saveRefreshToken = async (refreshToken) => {
  const client = new Client(clientConfig);

  try {
    await client.connect();

    const queryText = `
      INSERT INTO refresh_tokens (
        valid_until,
        token
      ) VALUES (
        to_timestamp($1 / 1000.0),
        $2
      );
    `;
    const tokenDuration = Date.now() + FIVE_MINUTES;
    const values = [tokenDuration, refreshToken];

    await client.query(queryText, values);
  } catch (err) {
    console.log(err.message);
  } finally {
    client.end();
  }
};

export const getRefreshTokenDuration = async (refreshToken) => {
  const client = new Client(clientConfig);

  try {
    await client.connect();

    const queryText = `
      SELECT valid_until FROM refresh_tokens WHERE token = $1;
    `;
    const result = await client.query(queryText, [refreshToken]);

    return result.rows[0].valid_until;
  } catch (err) {
    console.log(`Could not find refresh token in db: ${err.message}`);
  } finally {
    client.end();
  }
}

export const extendRefreshTokenDuration = async (refreshToken) => {
  const client = new Client(clientConfig);

  try {
    await client.connect();

    const queryText = `
      UPDATE refresh_tokens SET valid_until = to_timestamp($1 / 1000.0) WHERE token = $2;
    `;
    const tokenDuration = Date.now() + FIVE_MINUTES;
    const values = [tokenDuration, refreshToken];

    await client.query(queryText, values);
  } catch (err) {
    console.log(`Could not extend refresh tokens duration: ${err.message}`);
  } finally {
    client.end();
  }
}

export const deleteRefreshToken = async (refreshToken) => {
  const client = new Client(clientConfig);

  try {
    await client.connect();

    const queryText = `DELETE FROM refresh_tokens WHERE token = $1;`;

    await client.query(queryText, [refreshToken]);
  } catch (err) {
    console.log(`Could not remove refresh token from DB: ${err.message}`);
  } finally {
    client.end();
  }
}

