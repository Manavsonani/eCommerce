const { User } = require("../model/User");
const crypto = require("crypto");
const { sanitizeUser, sendMail } = require("../services/common");

const jwt = require("jsonwebtoken");
const { log } = require("console");


exports.createUser = async (req, res) => {
  // console.log(req.body);

  try {

    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {

        const user = new User({ ...req.body, password: hashedPassword, salt });
        // console.log(user);

        const doc = await user.save();

        req.login(sanitizeUser(doc), (err) => {

          if (err) {
            res.status(400).json(err);
          }
          else {
            const token = jwt.sign(sanitizeUser(doc), process.env.JWT_SECRET_KEY);

            res.cookie("jwt", token, {
              expires: new Date(Date.now() + 3600000),
              httpOnly: true,
            })
              .status(201)
              .json({ id: doc.id, role: doc.role });
          }
        });
      }
    );

  }
  catch (err) {
    res.status(400).json(err);
  }
};


exports.loginUser = async (req, res) => {
  // console.log(req.user);
  const user = req.user;
  res.cookie("jwt", user.token, {
    expires: new Date(Date.now() + 3600000),
    httpOnly: true,
  })
    .status(201)
    .json({ id: user.id, role: user.role });
};


exports.logout = async (req, res) => {
  // console.log(req.user);
  const user = req.user;
  res.cookie("jwt", null, {
    expires: new Date(Date.now() ),
    httpOnly: true,
  })
    .sendStatus(200)
    
};


exports.checkAuth = async (req, res) => {
  // console.log(req.user);

  if (req.user) {
    res.json(req.user);
  }
  else {
    res.sendStatus(401);
  }

};


exports.resetPasswordRequest = async (req, res) => {
  const email = req.body.email;
  // console.log(req.body.email);
  const user = await User.findOne({ email: email });

  if (user) {
    const token = crypto.randomBytes(48).toString('hex');
    user.resetPasswordToken = token;
    await user.save()

    const resetPageLink = "http://localhost:3000/reset-password?token=" + token + '&email=' + email;
    const subject = "Reset password for your e-commerce account ";
    const html = `<p> Click <a href='${resetPageLink}'>here</a> to Reset your password </p>`;
    if (email) {
      const response = await sendMail({ to: email, subject, html });
      console.log(response);
      res.json(response)

    }
    else {
      res.sendStatus(400);
    }
  } else {
    res.sendStatus(400);

  }
};


exports.resetPassword = async (req, res) => {
  const { email, password, token } = req.body;
  // console.log(req.body.email);
  const user = await User.findOne({ email: email, resetPasswordToken: token });

  if (user) {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {
        user.password = hashedPassword;
        user.salt = salt;
        await user.save()

        const subject = "Successfully password reset for your e-commerce account ";
        const html = `<p> Successfully Reset your password </p>`;
        if (email) {
          const response = await sendMail({ to: email, subject, html });
          console.log(response);
          res.json(response)

        }
        else {
          res.sendStatus(400);
        }
      })


  } else {
    res.sendStatus(400);

  }
};
