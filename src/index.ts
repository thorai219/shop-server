import mongoose from "mongoose"
import express, { Request, Response, NextFunction } from "express"
import cors from "cors"
import passport from "passport"
import passportLocal from "passport-local"
import cookieParser from "cookie-parser"
import session from "express-session"
import bcrypt from "bcryptjs"
import User from "./models/User"
import dotenv from "dotenv"
import { UserInterface, DatabaseUserInterface } from "./interface/UserInterface"

const LocalStrategy = passportLocal.Strategy

dotenv.config()

mongoose.connect(
  `mongodb+srv://${process.env.MONGO_USERNAME}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_CLUSTER}`,
  (err) => {
    if (err) throw err
    console.log("Connected To Mongo")
  }
)

const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(cors({ origin: "http://localhost:8080", credentials: true }))
app.use(
  session({
    secret: "sksms-qkqhek",
    resave: true,
    saveUninitialized: true
  })
)
app.use(passport.initialize())
app.use(passport.session())

passport.use(
  new LocalStrategy((username: string, password: string, done) => {
    User.findOne({ username: username }, (err: Error, user: DatabaseUserInterface) => {
      if (err) throw err
      if (!user) return done(null, false)
      bcrypt.compare(password, user.password, (err: Error, result: boolean) => {
        if (err) throw err
        if (result) {
          return done(null, user)
        } else {
          return done(null, false)
        }
      })
    })
  })
)

passport.serializeUser((user: DatabaseUserInterface, cb) => {
  cb(null, user._id)
})

passport.deserializeUser((id: string, cb) => {
  User.findOne({ _id: id }, (err: Error, user: DatabaseUserInterface) => {
    const userInformation: UserInterface = {
      username: user.username,
      isAdmin: user.isAdmin,
      id: user._id
    }
    cb(err, userInformation)
  })
})

app.post("/register", async (req, res) => {
  const { username, password } = req?.body
  if (!username || !password || typeof username !== "string" || typeof password !== "string") {
    res.send("Improper Values")
  }
  User.findOne({ username }, async (err: any, doc: DatabaseUserInterface) => {
    if (err) throw err
    if (doc) res.send("User Already Exists")
    if (!doc) {
      const hashedPassword = await bcrypt.hash(password, 10)
      const newUser = new User({
        username,
        password: hashedPassword
      })
      await newUser.save()
      res.send("success")
    }
  })
})

const isAdmin = (req: Request, res: Response, next: NextFunction) => {
  const { user }: any = req
  if (user) {
    User.findOne({ username: user.username }, (err: any, doc: DatabaseUserInterface) => {
      if (err) res.send("user doesn't exist")
      if (doc?.isAdmin) {
        next()
      } else {
        res.send("not admin")
      }
    })
  } else {
    res.send("need auth")
  }
}

app.post("/login", passport.authenticate("local"), async (req, res) => {
  res.send("logged in")
})

app.get("/logout", (req, res) => {
  req.logOut()
  res.send("logging out")
})

app.get("/user", async (req, res) => {
  try {
    res.send(req.user)
  } catch (err) {
    console.log(err)
  }
})

app.post("/deleteuser", isAdmin, async (req, res) => {
  const { id } = req.body
  await User.findByIdAndDelete({ _id: id }, {}, (err) => {
    if (err) res.send("error")
    res.send("deleted")
  })
})

app.get("/getallusers", isAdmin, async (req, res) => {
  await User.find({}, (err, data: DatabaseUserInterface[]) => {
    if (err) res.send("error")

    const filteredUser: UserInterface[] = []
    data.forEach((item: DatabaseUserInterface) => {
      filteredUser.push({
        id: item._id,
        username: item.username,
        isAdmin: item.isAdmin
      })
    })
    res.send(filteredUser)
  })
})

app.listen(4000, () => {
  console.log("Server Started")
})
