import "dotenv/config";
import pkg from "pg";
import bcrypt from "bcrypt";

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

