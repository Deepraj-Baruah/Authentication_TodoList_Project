import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
    user: process.env.USER,
    host: process.env.HOST,
    database: process.env.DATABASE,
    password: process.env.PASSWORD,
    port: process.env.PORT,
});
db.connect();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24,
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/secrets", async (req, res) => {
    console.log(req.user);
    if (req.isAuthenticated()) {
        try {
            const result = await db.query(
                "SELECT * FROM users JOIN todolist ON users.id = todolist.user_id WHERE email = $1",
                [req.user.email]);
            console.log(result.rows[0]);
            if (result.rows.length > 0) {
                const title = result.rows.map(row => row.title);
                const name = result.rows[0].username;
                res.render("secret.ejs", {
                    title: title,
                    name: name,
                });
            } else {
                res.render("secret.ejs", {
                    secret: "You should submit a secret?"
                });
            }
        } catch (error) {
            console.log(error);
        }
    } else {
        res.redirect("/");
    }
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit.ejs");
    } else {
        res.redirect("/login");
    }
});

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const check = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (check.rows.length > 0) {
            res.send("Email already exists. Try to login.");
        } else {
            const hash = await bcrypt.hash(password, saltRounds);
            const result = await db.query(
                "INSERT INTO users(username, email, password) VALUES($1, $2, $3) RETURNING *",
                [username, email, hash]);
            const user = result.rows[0];
            req.login(user, (err) => {
                console.log(err);
                res.redirect("/secrets");
            });
        }
    } catch (error) {
        console.log(error);
        res.send("An error occurred. Please try again.");
    }
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"],
})
);

app.get("/auth/google/secrets-blog", passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/",
}));

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.log(err);
        res.redirect("/");
    });
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/",
}));

app.post("/submit", async (req, res) => {
    const title = req.body.secret;
    console.log(req.user);
    try {
        const result = await db.query("INSERT INTO todolist(title, user_id) VALUES($1, $2)",
            [title, req.user.id]);
        res.redirect("/secrets")
    } catch (error) {
        console.log(error);
    }
});

app.get("/delete/:id", async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const deleteTodolist = await db.query(
            "DELETE FROM todolist WHERE todolist.id = ($1) RETURNING *",
            [id]);
        if (deleteTodolist.rows.length === 0) {
            return res.status(404).send("Todo not deleted");
        }
        console.log("Deleted Todolist: ", deleteTodolist.rows);
        res.redirect("/secrets");
    } catch (error) {
        console.log(error);
    }
});

passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return cb(null, user);
            } else {
                return cb(null, false, { message: "Incorrect password. Try again." });
            }
        } else {
            return cb(null, false, { message: "User not found." });
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets-blog",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
    // console.log(profile);
    try {
        const result = await db.query(
            "SELECT * FROM users WHERE email = $1",
            [profile.email]);
        if (result.rows.length === 0) {
            const newUser = await db.query(
                "INSERT INTO users(username, email, password) VALUES($1, $2, $3)",
                [profile.displayName, profile.email, "google"]);
            return cb(null, newUser.rows[0]);
        } else {
            return cb(null, result.rows[0]);
        }
    } catch (error) {
        return cb(error);
    }
})
);

passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        if (result.rows.length > 0) {
            cb(null, result.rows[0]);
        } else {
            cb(new Error("User not found"));
        }
    } catch (err) {
        cb(err);
    }
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
