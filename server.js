const express = require("express");
const mysql = require("mysql2");
require("dotenv").config();
const app = express();
const cors = require("cors");
const bcrypt = require("bcrypt");
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: process.env.host,
  user: process.env.user,
  password: process.env.password,
  database: process.env.database,
  connectTimeout: 0,
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Check if username or email already exists
  const checkQuery = "SELECT * FROM login WHERE name = ? OR email = ? ";
  db.query(checkQuery, [name, email], async (err, results) => {
    if (err) {
      res.status(500).json({ message: "Error checking user details" });
      return;
    }
    if (results.length > 0) {
      const existingUser = results.find(
        (user) => user.name === name || user.email === email
      );
      if (existingUser.name === name) {
        res.status(409).json({ message: "Username already exists" });
      } else if (existingUser.email === email) {
        res.status(409).json({ message: "Email already exists" });
      }
      return;
    }

    // Encrypt the password before storing in the database
    const hashedPassword = (await bcrypt.hash(password, 10)).substring(0, 10);

    // If  email and name are unique, create the new user
    const insertQuery =
      "INSERT INTO login (name, email , password) VALUES (?, ?, ?)";
    db.query(insertQuery, [name, email, hashedPassword], (err, results) => {
      if (err) {
        console.log("error in inserting", err);
        res.status(500).json({ message: "Error creating user" });
        return;
      }
      res.status(200).json({ message: "User registered successfully" });
    });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM login WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) {
      console.log("db query err", err);
      return res.json({ Error: "Login error in server" });
    }
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err) {
            console.log("Login err", err);
            return res.json({ Error: "Password compare error" });
          }
          if (response) {
            return res.json({ Status: "Success" });
          } else {
            return res.json({ Error: "Passwords not matched" });
          }
        }
      );
    } else {
      return res.json({ Error: "No User Found" });
    }
  });
});

// app.post('/login', (req, res) => {
//   const { email, password } = req.body;

//   const sql = 'SELECT * FROM users WHERE email = ? AND password = ?';
//   db.query(sql, [email, password], (err, results) => {
//     if (err) {
//       res.status(500).json({ message: 'Error logging in' });
//       return;
//     }
//     if (results.length > 0) {
//       res.status(200).json({ message: 'Login successful' });
//     } else {
//       res.status(401).json({ message: 'Invalid credentials' });
//     }
//   });
// });

app.listen(3306, () => {
  console.log("server is running");
});
