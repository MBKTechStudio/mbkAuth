import pkg from "pg";
const { Pool } = pkg;
import dotenv from "dotenv";

dotenv.config();

// PostgreSQL connection pool for pool
const poolConfig = {
  connectionString: process.env.NEON_POSTGRES,
  ssl: {
    rejectUnauthorized: true,
  },

};

export const dblogin = new Pool(poolConfig);

// Test connection for pool
(async () => {
  try {
    const client = await dblogin.connect();
    const dbName = process.env.IsDeployed === "true" ? "Neon" : "local";
    console.log("Connected to " + dbName + " PostgreSQL database (pool)!");
    client.release();
  } catch (err) {
    console.error("Database connection error (pool):", err);
  }
})();