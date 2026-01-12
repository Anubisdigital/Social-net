import express from "express";
import cors from "cors";

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage (replace with DB or GitHub later)
let DATA = {
  posts: [],
  users: [],
  likes: [],
  comments: [],
  reports: [],
  follows: []
};

// Load data
app.get("/api/load", (req, res) => {
  res.json(DATA);
});

// Save data
app.post("/api/save", (req, res) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    return res.status(400).json({ error: "Invalid data" });
  }

  DATA = {
    posts: body.posts || [],
    users: body.users || [],
    likes: body.likes || [],
    comments: body.comments || [],
    reports: body.reports || [],
    follows: body.follows || []
  };

  res.json({ success: true });
});

// Health check
app.get("/", (req, res) => {
  res.send("CarbonKind backend running");
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Backend running on http://localhost:${PORT}`);
});
