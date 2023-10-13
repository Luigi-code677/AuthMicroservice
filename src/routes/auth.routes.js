import express from "express";
import {
  register,
  login,
  confirmAccount,
  forgetPassword
} from "../controllers/auth.controller.js";
import authentication from "../middleware/authentication.middleware.js";

const router = express.Router();

router.post("/register", register);
router.get("/confirm/:token", confirmAccount);
router.post("/login", login);
router.patch("/change-password", forgetPassword);
router.route("/change-password/:token").get(authentication).post(forgetPassword);

export default router;
