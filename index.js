import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 15
  }
}));

app.use(passport.initialize());
app.use(passport.session());


app.get("/", (req, res) => {
  res.render("home.ejs", {logreg: "login/register"});
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/login", (req, res) => {
  res.render("login.ejs", {logreg: "login/register"});
});


app.get("/register", (req, res) => {
  res.render("register.ejs", {logreg: "login/register"});
});

app.get("/afterLogin", (req, res) => {
  const user = req.user;
  if(req.isAuthenticated()) res.render("afterLogin.ejs", {user: user});
  else res.redirect("/login");
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}));

app.get("/auth/google/afterLogin", passport.authenticate("google", {
  successRedirect: "/afterLogin",
  failureRedirect: "/login"
}));

app.post("/register", async (req, res) => {
  const name = req.body.name;
  const email = req.body.username;
  const password = req.body.password;
  const phone = req.body.phone; 
  const recheck = req.body.recheck; 

  if(email.length == 0) res.render("register.ejs", {error: "*Email cannot be empty."});
  else if(name.length == 0) res.render("register.ejs",{error: "*Name cannot be empty."});
  else if(phone.length == 0) res.render("register.ejs", {error: "*Phone number cannot be empty."});
  else if(password.length == 0) res.render("register.ejs", {error: "*Password cannot be empty."});
  else if(recheck.length == 0) res.render("register.ejs", {error: "*Recheck cannot be empty."});
  else if(password != recheck) res.render("register.ejs", {password_mismatch: "*Password doesn't match."});

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1 or phone = $2", [
      email, phone
    ]);

    if (checkResult.rows.length > 0) res.render("register.ejs",{email_exists: "*Email/Phone already exists."});
    else {
      bcrypt.hash(password, saltRounds, async(err, hash)=>{
        if(err){
          console.log(err);
        }else{
          const result = await db.query(
            "INSERT INTO users (email, phone, password, name) VALUES ($1, $2, $3, $4) RETURNING *;",
            [email, phone, hash, name]
          );

          const user = result.rows[0]; 
          console.log(result);
          req.login(user, (err)=>{
            console.log(err);
            res.redirect("/afterLogin");
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


const validateCredentials = ( req, res, next )=>{
  const { username, password } = req.body;

  if(!username) return res.render("login.ejs", {logreg: "login/register", error: "*Username cannot be empty."});
  else if(!password) return res.render("login.ejs", {logreg: "login/register", error: "*Password cannot be empty."});
  
  next();
}

app.post("/login", validateCredentials, 
(req, res, next) => {
    passport.authenticate("local", (err, user, info)=>{
    
    console.log(info);
    if(err) res.status(500).send(err.message);

    if(!user && info.message === "*Incorrect Password.") 
      return res.render("login.ejs", {logreg:"login/register", error: info.message});

    else if(!user) return res.render("login.ejs", {logreg: "login/register", email_dne: info.message});
      
    return res.redirect("/afterLogin");

}) (req, res, next);
});




passport.use("local", new Strategy( async function verify(username, password, cb ){
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username
    ]);
  
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.password;
  
      bcrypt.compare(password, storedPassword, (err, result)=>{
        if(err) return cb(err);
        else{
          if ( result ) return cb(null, user);
          else return cb(null, false, {message: "*Incorrect Password."});
        }
      });

    } else{
      return cb(null, false, {message: "*Email doesn't exist."});
    }

  } catch (err) { return cb(err); }
}));

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/afterLogin",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async(accessToken, refreshToken, profile, cb) => {
  try{
    const result = await db.query("SELECT * FROM users WHERE email = $1;", [profile.email]);
    if(result.rows.length === 0){
      const newUser = await db.query("INSERT INTO users (email, password, name) VALUES ($1, $2, $3) returning *;", 
        [profile.email, "google", profile.displayName]);
      return(null, newUser.rows[0]);
    }else return cb(null, result.rows[0]);

  }catch(err){ return cb(err); }
} 

));


passport.serializeUser((user, cb)=>{ cb(null, user); });
passport.deserializeUser((user, cb)=>{ cb(null, user); });

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
