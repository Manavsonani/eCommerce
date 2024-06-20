
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