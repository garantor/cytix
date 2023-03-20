import dotenv from "dotenv";

dotenv.config();

export const config = {
  apiUrl: process.env.API_URL as string,
  username: process.env.USERNAME as string,
  password: process.env.PASSWORD as string,
  scanUrl: process.env.SCAN_URL as string
};

