import express from 'express'
import UserController from '../controller/userController.js';
import checkToken from '../middleware/checkToken.js'

const router = express.Router()

router.get("/", UserController.helloWorld)
router.get("/:id", checkToken ,UserController.getUserById)
router.post("/register", UserController.createUser)
router.post("/login", UserController.loginUser)
router.get("/list/all", checkToken, UserController.listAllUsers)

export default router;
