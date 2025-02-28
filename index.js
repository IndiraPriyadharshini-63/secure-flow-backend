const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cors());

const users = [];
const crypto = require("crypto");
const secret = crypto.randomBytes(64).toString("hex");

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    //     if (!username || !password) {
    //       return res.status(400).send("Username and password are required");
    //     }
    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ username, password: hashedPassword });
    res.status(201).send("User registered successfully");
  } catch (error) {
    res.status(500).send("Error registering user");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    //     if (!username || !password) {
    //       return res.status(400).send("Username and password are required");
    //     }
    const user = users.find((u) => u.username === username);

    if (!user) {
      return res.status(400).send("User not found");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).send("Invalid password");
    }
    const token = jwt.sign({ username: user.username }, secret, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (error) {
    res.status(500).send("Error logging in");
  }
});

app.get("/protected", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(403).send("Token required");
  }

  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      return res.status(403).send("Invalid token");
    }
    res.json({ message: "Protected data", user: decoded.username });
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
