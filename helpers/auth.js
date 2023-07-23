import "dotenv/config";
import bcrypt from "bcrypt";

export const encryptPassword = async password => {
  const salt = await bcrypt.genSalt(12);
  const hash = await bcrypt.hash(password, salt);

  return hash;
};

export const validPassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

export const isValidToken = tokenDuration => Date.parse(tokenDuration) > Date.now();
