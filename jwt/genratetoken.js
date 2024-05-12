const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const generateJwt = (userId) => {
    const token = jwt.sign( userId, process.env.jwtSecret, { expiresIn: "1h" });
    return token;
};

module.exports = { generateJwt };
