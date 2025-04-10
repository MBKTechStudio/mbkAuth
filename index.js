import dotenv from "dotenv";
import router from "./lib/main.js";
dotenv.config();
export { validateSession, checkRolePermission, validateSessionAndRole, getUserData } from "./lib/validateSessionAndRole.js";
export { authenticate } from "./lib/auth.js";
export { dblogin } from "./lib/pool.js";
export default router;