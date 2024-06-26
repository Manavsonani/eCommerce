const nodemailer = require('nodemailer');
const passport = require('passport');

exports.isAuth = (req, res, done) => {
    return passport.authenticate('jwt')
}


exports.sanitizeUser = (user) => {
    return { id: user.id, role: user.role }
}

exports.cookieExtractor = function (req) {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['jwt']
    }
    // token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2NjZjOTdmMzk4OWViZjE0YmRhMGE0NiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzE4MjgwMjYxfQ.KlY857SekALVFntFdTBfEsw1AMq2SiZl0bZX0toTdPo";
    return token;
}

//----------- mail --------------------
 let transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // Use `true` for port 465, `false` for all other ports
    auth: {
        user: "sonani1214@gmail.com", //gmail
        pass: process.env.MAIL_PASSWORD, //password
    },
});
exports.sendMail = async function ({ to, subject, text, html }) {

    let info = await transporter.sendMail({
        from: '"E-commerce" <sonani1214@gmail.com>',
        to,
        subject,
        text,
        html,
    });
    return info;


}