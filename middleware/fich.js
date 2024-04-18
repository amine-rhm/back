const multer = require('multer');
const path = require("path");
const fs = require("fs");

const __dirnameResolved = path.resolve();
console.log("__dirname : ", __dirnameResolved);
const uploadFolder = path.join(__dirnameResolved, "./public/uploads");
console.log("uploadFolder : ", uploadFolder);

fs.mkdirSync(uploadFolder, { recursive: true });

const storage = multer.diskStorage({
  destination: (request, file, callback) => {
    console.log("file : ", file);
    callback(null, uploadFolder);
  },
  filename: (request, file, callback) => {
    console.log("file from filename function : ", file);

    const uniquePrefix =
      new Date().toLocaleString("sv-SE").replace(/[\s\:]/g, "-") +
      "-" +
      Math.round(Math.random() * 1e9);
    const extension = path.extname(file.originalname);
    console.log("filename : ", uniquePrefix + extension);
    callback(null, uniquePrefix + extension);
  },
});

const upload = multer({
  storage: storage,
  fileFilter: function (request, file, callback) {
    if (
      file.mimetype === "image/png" ||
      file.mimetype === "image/jpg" ||
      file.mimetype === "image/jpeg"
    ) {
      callback(null, true);
    } else {
      console.log("Only .png .jpg file supported!");
      callback(null, false);
    }
  },
  limits: { fileSize: 1024 * 1024 * 3 },
});

module.exports = { upload, storage };
