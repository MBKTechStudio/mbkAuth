import express from "express";
import crypto from "crypto";
import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import dotenv from "dotenv";
import { dblogin } from "./pool.js";
import { authenticate } from "./auth.js";
import fetch from 'node-fetch';
import cookieParser from "cookie-parser"; // Import cookie-parser

dotenv.config();
const router = express.Router();
const cookieExpireTime = 2 * 24 * 60 * 60 * 1000; // 12 hours
// cookieExpireTime: 2 * 24 * 60 * 60 * 1000, 2 day
// cookieExpireTime:  1* 60 * 1000, 1 min 
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

router.use(
  session({
    store: new PgSession({
      pool: dblogin, // Connection pool
      tableName: "session", // Use another table-name than the default "session" one
    }),
    secret: process.env.session_seceret_key, // Replace with your secret key
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: cookieExpireTime,
      domain: process.env.IsDeployed === 'true' ? '.mbktechstudio.com' : undefined, // Use root domain for subdomain sharing
      httpOnly: true,
      secure: process.env.IsDeployed === 'true', // Use secure cookies in production
    },
  })
);

router.use(cookieParser()); // Use cookie-parser middleware

router.use((req, res, next) => {
  if (req.session && req.session.user) {
    const userAgent = req.headers["user-agent"];
    const userIp =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const formattedIp = userIp === "::1" ? "127.0.0.1" : userIp;

    req.session.otherInfo = {
      ip: formattedIp,
      browser: userAgent,
    };

    next();
  } else {
    next();
  }
});

// Save the username in a cookie, the cookie user name is use
// for displaying user name in profile menu. This cookie is not use anyelse where.
// So it is safe to use.
router.use(async (req, res, next) => {
  if (req.session && req.session.user) {
    try {

      res.cookie("username", req.session.user.username, {
        maxAge: cookieExpireTime,
      });

      const query = `SELECT "Role" FROM "Users" WHERE "UserName" = $1`;
      const result = await dblogin.query(query, [req.session.user.username]);

      if (result.rows.length > 0) {
        req.session.user.role = result.rows[0].Role;
        res.cookie("userRole", req.session.user.role, {
          maxAge: cookieExpireTime,
        });
      } else {
        req.session.user.role = null;
      }
    } catch (error) {
      console.error("Error fetching user role:", error.message);
      req.session.user.role = null; // Fallback to null role
    }
  }
  next();
});

router.use(async (req, res, next) => {
  // Check for sessionId cookie if session is not initialized
  if (!req.session.user && req.cookies && req.cookies.sessionId) {
    console.log("Restoring session from sessionId cookie"); // Log session restoration
    const sessionId = req.cookies.sessionId;
    const query = `SELECT * FROM "Users" WHERE "SessionId" = $1`;
    const result = await dblogin.query(query, [sessionId]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      req.session.user = {
        id: user.id,
        username: user.UserName,
        sessionId,
      };
      console.log(`Session restored for user: ${user.UserName}`); // Log successful session restoration
    } else {
      console.warn("No matching session found for sessionId"); // Log if no session is found
    }
  }
  next();
});

//Invoke-RestMethod -Uri http://localhost:3030/terminateAllSessions -Method POST
// Terminate all sessions route
router.post("/api/mbkauth/terminateAllSessions", authenticate(process.env.Main_SECRET_TOKEN), async (req, res) => {
  try {
    await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL`);

    // Clear the session table
    await dblogin.query('DELETE FROM "session"');

    // Destroy all sessions on the server
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res
          .status(500)
          .json({ success: false, message: "Failed to terminate sessions" });
      }
      console.log("All sessions terminated successfully");
      res.status(200).json({
        success: true,
        message: "All sessions terminated successfully",
      });
    });
  } catch (err) {
    console.error("Database query error during session termination:", err);
    res
      .status(500)
      .json({ success: false, message: "Internal Server Error" });
  }
}
);

router.post("/api/mbkauth/login", async (req, res) => {
  console.log("Login request received"); // Log when login is initiated

  const { username, password, token, recaptcha } = req.body;
  console.log(`Login attempt for username: ${username}`); // Log username

  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptcha}`;

  // Bypass recaptcha for specific users
  if (username !== "ibnekhalid" && username !== "maaz.waheed" && username !== "support") {
    try {
      const response = await fetch(verificationUrl, { method: 'POST' });
      const body = await response.json();
      console.log("reCAPTCHA verification response:", body); // Log reCAPTCHA response

      if (!body.success) {
        console.error("Failed reCAPTCHA verification");
        return res.status(400).json({ success: false, message: "Failed reCAPTCHA verification" });
      }
    } catch (err) {
      console.error("Error during reCAPTCHA verification:", err);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  }

  if (!username || !password) {
    console.error("Missing username or password");
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  try {
    // Query to check if the username exists
    const userQuery = `SELECT * FROM "Users" WHERE "UserName" = $1`;
    const userResult = await dblogin.query(userQuery, [username]);
    console.log("User query result:", userResult.rows); // Log user query result

    if (userResult.rows.length === 0) {
      console.error(`Username does not exist: ${username}`);
      return res.status(404).json({ success: false, message: "Username does not exist" });
    }

    const user = userResult.rows[0];

    // Check if the password matches
    if (user.Password !== password) {
      console.error(`Incorrect password for username: ${username}`);
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // Check if the account is inactive
    if (!user.Active) {
      console.error(`Inactive account for username: ${username}`);
      return res.status(403).json({ success: false, message: "Account is inactive" });
    }

    if ((process.env.mbkauthTwoFAenable || "").toLocaleLowerCase() === "true") {
      let sharedSecret;
      const query = `SELECT "TwoFAStatus", "TwoFASecret" FROM "TwoFA" WHERE "UserName" = $1`;
      const twoFAResult = await dblogin.query(query, [username]);
      console.log("TwoFA query result:", twoFAResult.rows); // Log TwoFA query result

      sharedSecret = twoFAResult.rows[0]?.TwoFASecret;
      if (twoFAResult.rows.length > 0 && twoFAResult.rows[0].TwoFAStatus && !token) {
        console.error("2FA code required but not provided");
        return res.status(401).json({ success: false, message: "Please Enter 2FA code" });
      }

      if (token && twoFAResult.rows[0]?.TwoFAStatus) {
        const tokenValidates = speakeasy.totp.verify({
          secret: sharedSecret,
          encoding: "base32",
          token: token,
          window: 1, // Allows a margin for clock drift, optional
        });

        if (!tokenValidates) {
          console.error(`Invalid 2FA code for username: ${username}`);
          return res.status(401).json({ success: false, message: "Invalid 2FA code" });
        }
      }
    }
    
    // Generate session ID
    const sessionId = crypto.randomBytes(256).toString("hex");
    console.log(`Generated session ID for username: ${username}`); // Log session ID

    await dblogin.query(`UPDATE "Users" SET "SessionId" = $1 WHERE "id" = $2`, [
      sessionId,
      user.id,
    ]);

    // Store session ID in session
    req.session.user = {
      id: user.id,
      username: user.UserName,
      sessionId,
    };

    // Set a cookie accessible across subdomains
    res.cookie("sessionId", sessionId, {
      maxAge: cookieExpireTime,
      domain: process.env.IsDeployed === 'true' ? '.mbktechstudio.com' : undefined, // Use domain only in production
      httpOnly: true,
      secure: process.env.IsDeployed === 'true', // Use secure cookies in production
    });

    console.log(`User "${username}" logged in successfully`);
    res.status(200).json({
      success: true,
      message: "Login successful",
      sessionId,
    });
  } catch (err) {
    console.error("Error during login process:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/api/mbkauth/logout", async (req, res) => {
  if (req.session.user) {
    try {
      const { id, username } = req.session.user;
      const query = `SELECT "Active" FROM "Users" WHERE "id" = $1`;
      const result = await dblogin.query(query, [id]);

      if (result.rows.length > 0 && !result.rows[0].Active) {
        console.log("Account is inactive during logout");
      }

      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }
        // Clear both session cookies
        res.clearCookie("connect.sid");
        res.clearCookie("sessionId"); // Clear the sessionId cookie used for restoration
        console.log(`User "${username}" logged out successfully`);
        res.status(200).json({ success: true, message: "Logout successful" });
      });
    } catch (err) {
      console.error("Database query error during logout:", err);
      res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  } else {
    res.status(400).json({ success: false, message: "Not logged in" });
  }
});

export default router;