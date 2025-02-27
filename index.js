import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session, { Cookie } from "express-session";
import { Strategy } from "passport-local";
import env from "dotenv";
const app = express();
const port = 3000;

const saltRounds = 10;
env.config();
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
const { Pool, Client } = pg;
const db = new Client({
  user: "postgres",
  password: process.env.DATABASE_SECRET,
  host: "localhost",
  port: 5432,
  database: "ownProject",
});
await db.connect();
app.post("/createUser", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  try {
    await db.query(
      `INSERT INTO userInfos (role_id,email,password) VALUES ($1 ,$2, $3)`,
      [1, email, password]
    );
    res.status(201).json({ message: "create data" });
  } catch (err) {
    console.log(err);
    res.status(404).json(err.detail);
  }
});
app.post("/createPost", async (req, res) => {
  const title = req.body.title;
  const content = req.body.content;
  // wait for session manipulate
  const author_id = req.body.author_id;
  const img_path = req.body.img_path;
  try {
    await db.query(
      `INSERT INTO postInfos (title,content,author_id,img_path) VALUES ($1 ,$2, $3,$4)`,
      [title, content, author_id, img_path]
    );
    res.status(201).json({ message: "create data" });
  } catch (err) {
    console.log(err);
    res.status(404).json(err.detail);
  }
});
app.post("/createRole", async (req, res) => {
  const roleName = req.body.roleName;

  try {
    await db.query(`INSERT INTO roles (role_name) VALUES ($1)`, [roleName]);
    res.status(201).json({ message: "create data" });
  } catch (err) {
    console.log(err);
    res.status(404).json(err.detail);
  }
});
app.get("/posts", async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM postInfos`);
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(404).json(err.detail);
  }
});

app.put("/post/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  const title = req.body.title || "";
  const content = req.body.content || "";
  const img_path = req.body.img_path || "";
  console.log("called", id);
  try {
    await db.query(
      `UPDATE postInfos SET title = $1, content = $2,img_path = $3 WHERE  postInfos.id = ${id}`,
      [title, content, img_path]
    );
    res.status(200).json({ message: "update data" });
  } catch (err) {
    res.status(404).json(err.detail);
  }
});
app.delete("/post/:id", async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    await db.query(`DELETE FROM postInfos WHERE postInfos.id = ${id}`);
    res.status(200).json({ message: "delete data" });
  } catch (err) {
    res.status(404).json(err.detail);
  }
});
app.get("/users", async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM users`);
    res.status(200).json(result.rows);
  } catch (err) {
    console.log(err);
  }
});
app.get("/roles", async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM roles`);
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(404).json(err.detail);
  }
});

app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
        message: "you have cookie",
        user: req.user,
    });
  } else {
    res.redirect("/login");
  }
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
  })
);
app.get('/login',(req,res) =>{
    res.json({
        message:"Please login.."
    })
})
app.get("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/home");
    });
  });
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const role_id = 1;
  try {
    const checkResult = await db.query(
      "SELECT * FROM userInfos WHERE email = $1",
      [email]
    );

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          try {
            const result = await db.query(
              "INSERT INTO users (email, password,role_id) VALUES ($1, $2,$3) RETURNING *",
              [email, hash, role_id]
            );
            const user = result.rows[0];
            req.login(user, (err) => {
              // res.status(200).json(user);
              //   console.log("success");
              res.redirect("/home");
            });
          } catch (err) {
            res.status(400).json(err.detail);
          }
        }
      });
    }
  } catch (err) {
    // console.log(err);
    res.status(400).json(err.detail);
  }
});

passport.use(
  new Strategy(async function verify(username, password, cb) {
    console.log("use Authenticate here");
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              console.log(user);
              return cb(null, user);
            } else {
              //Did not pass password check
              console.log("Your password not correct");
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`App running on port ...${port}`);
});
