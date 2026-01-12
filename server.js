 import express from "express";
import cors from "cors";
import fetch from "node-fetch"; // npm i node-fetch@2

const app = express();
const PORT = 3000;

// ⚠️ Hard-coded GitHub token (unsafe)
const GITHUB_TOKEN = "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";
const GIST_ID = null; // optional: your Gist ID if you have one

app.use(cors());
app.use(express.json());

// In-memory storage fallback
let DATA = {
  posts: [],
  users: [],
  likes: [],
  comments: [],
  reports: [],
  follows: []
};

// ========================
// Load data from GitHub Gist
// ========================
async function loadFromGist() {
  if (!GITHUB_TOKEN || !GIST_ID) return;

  try {
    const res = await fetch(`https://api.github.com/gists/${GIST_ID}`, {
      headers: {
        Authorization: `token ${GITHUB_TOKEN}`,
        Accept: "application/vnd.github.v3+json"
      }
    });

    if (!res.ok) throw new Error("Failed to load Gist");

    const gist = await res.json();
    const content = gist.files["carbonkind_data.json"]?.content;

    if (content) {
      const parsed = JSON.parse(content);
      DATA = parsed;
      console.log("✅ Loaded data from GitHub Gist");
    }
  } catch (err) {
    console.log("⚠️ Could not load from Gist, using memory fallback");
  }
}

// ========================
// Save data to GitHub Gist
// ========================
async function saveToGist() {
  if (!GITHUB_TOKEN) return;

  const gistData = {
    files: {
      "carbonkind_data.json": {
        content: JSON.stringify(DATA, null, 2)
      }
    },
    public: false,
    description: "CarbonKind Social Network Data"
  };

  try {
    if (GIST_ID) {
      await fetch(`https://api.github.com/gists/${GIST_ID}`, {
        method: "PATCH",
        headers: {
          Authorization: `token ${GITHUB_TOKEN}`,
          Accept: "application/vnd.github.v3+json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify(gistData)
      });
    } else {
      const res = await fetch(`https://api.github.com/gists`, {
        method: "POST",
        headers: {
          Authorization: `token ${GITHUB_TOKEN}`,
          Accept: "application/vnd.github.v3+json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify(gistData)
      });

      const gist = await res.json();
      console.log("✅ Created new Gist:", gist.id);
    }
  } catch (err) {
    console.log("⚠️ Failed to save to GitHub Gist");
  }
}

// ========================
// API routes
// ========================

// Health check
app.get("/", (req, res) => {
  res.send("CarbonKind backend running");
});

// Load data
app.get("/api/load", async (req, res) => {
  await loadFromGist();
  res.json(DATA);
});

// Save data
app.post("/api/save", async (req, res) => {
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

  await saveToGist();
  res.json({ success: true });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Backend running on http://localhost:${PORT}`);
});
