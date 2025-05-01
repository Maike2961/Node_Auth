import express from 'express'
import mongoose from 'mongoose'
import dotenv from 'dotenv'
import userRoutes from './router/userRouter.js';

dotenv.config()
const app = express()

app.use(express.json())

app.use("/user", userRoutes)

app.listen(
    process.env.PORT,
    mongoose.connect(`mongodb://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_MONGO}?authSource=admin`)
    .then(() => console.log('connected'))
    .catch((e) => console.error(e))
)