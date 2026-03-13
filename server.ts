import express from "express";
import { createServer as createViteServer } from "vite";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("database.db");
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    fullName TEXT,
    mobile TEXT,
    unionName TEXT,
    orgName TEXT,
    headName TEXT,
    headDesignation TEXT,
    orgAddress TEXT,
    contactMobile TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'pending'
  )
`);

// Ensure columns exist for existing databases
try { db.exec("ALTER TABLE users ADD COLUMN fullName TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN mobile TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN orgName TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN headName TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN headDesignation TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN orgAddress TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN contactMobile TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN email TEXT"); } catch (e) {}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());
  app.use(cookieParser());

  // Middleware to verify JWT
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  // Auth Routes
  app.post("/api/auth/register", async (req, res) => {
    const { username, password, fullName, mobile, unionName } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const stmt = db.prepare("INSERT INTO users (username, password, fullName, mobile, unionName, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)");
      
      // First user is admin and approved
      const userCount = db.prepare("SELECT count(*) as count FROM users").get() as { count: number };
      const role = userCount.count === 0 ? "admin" : "user";
      const status = userCount.count === 0 ? "approved" : "pending";
      
      stmt.run(username, hashedPassword, fullName, mobile, unionName, role, status);
      res.json({ message: "Registration successful. Waiting for admin approval." });
    } catch (err: any) {
      res.status(400).json({ error: "Username already exists" });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as any;
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ 
      id: user.id, 
      username: user.username, 
      fullName: user.fullName,
      mobile: user.mobile,
      role: user.role, 
      status: user.status, 
      unionName: user.unionName 
    }, JWT_SECRET);
    res.cookie("token", token, { httpOnly: true, sameSite: "none", secure: true });
    res.json({ user: { 
      id: user.id, 
      username: user.username, 
      fullName: user.fullName,
      mobile: user.mobile,
      role: user.role, 
      status: user.status, 
      unionName: user.unionName,
      orgName: user.orgName,
      headName: user.headName,
      headDesignation: user.headDesignation,
      orgAddress: user.orgAddress,
      contactMobile: user.contactMobile,
      email: user.email
    } });
  });

  app.post("/api/auth/logout", (req, res) => {
    res.clearCookie("token");
    res.json({ message: "Logged out" });
  });

  app.get("/api/auth/me", (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.json({ user: null });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      // Refresh user data from DB to get latest status
      const user = db.prepare("SELECT id, username, fullName, mobile, role, status, unionName, orgName, headName, headDesignation, orgAddress, contactMobile, email FROM users WHERE id = ?").get(decoded.id) as any;
      res.json({ user });
    } catch (err) {
      res.json({ user: null });
    }
  });

  // Admin Routes
  app.get("/api/admin/users", authenticate, (req: any, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
    const users = db.prepare("SELECT id, username, fullName, mobile, unionName, role, status FROM users WHERE role != 'admin'").all();
    res.json(users);
  });

  app.post("/api/admin/users/:id/status", authenticate, (req: any, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
    const { id } = req.params;
    const { status } = req.body;
    db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, id);
    res.json({ message: "User status updated" });
  });

  // Profile Routes
  app.post("/api/user/profile", authenticate, (req: any, res) => {
    const { orgName, headName, headDesignation, orgAddress, contactMobile, email } = req.body;
    const userId = req.user.id;
    
    try {
      db.prepare(`
        UPDATE users 
        SET orgName = ?, headName = ?, headDesignation = ?, orgAddress = ?, contactMobile = ?, email = ?
        WHERE id = ?
      `).run(orgName, headName, headDesignation, orgAddress, contactMobile, email, userId);
      
      const updatedUser = db.prepare("SELECT id, username, fullName, mobile, role, status, unionName, orgName, headName, headDesignation, orgAddress, contactMobile, email FROM users WHERE id = ?").get(userId);
      res.json({ message: "Profile updated successfully", user: updatedUser });
    } catch (err) {
      res.status(500).json({ error: "Failed to update profile" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
