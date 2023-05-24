// import multer, { Multer } from "multer";
// import path from "path";
// import { Request,Response,NextFunction } from "express";


// const storage: multer.StorageEngine = multer.diskStorage({
//   destination: (req:Request, file, cb) => {
//     cb(null, 'uploads/');
//   },
//   filename: (req:Request, file, cb) => {
//     let ext = path.extname(file.originalname);
//     cb(null, Date.now() + ext);
//   },
// });

// const upload: Multer = multer({ storage });

// export default upload;

import multer, { Multer } from "multer";
import path from "path";
import { Request } from "express";

const storage: multer.StorageEngine = multer.diskStorage({
  destination: (req: Request, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req: Request, file, cb) => {
    let ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  },
});

const upload: Multer = multer({ storage });

export default upload;
