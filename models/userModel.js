import mongoose from 'mongoose'
const User = mongoose.model('User', {
    nome: String,
    idade: Number,
    email: String,
    senha: String,
})

export default User