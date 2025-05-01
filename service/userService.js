import bcrypt from 'bcrypt'
import User from '../models/userModel.js';

const UserService = {

    saveUser: async(nome, idade, email, senha)=>{
        const user = User({
            nome,
            idade,
            email,
            senha
        });

        return await user.save()
    },

    findByEmailAndNome: async(email, nome)=>{
        return await User.findOne({email, nome})
    },

    findById: async (id) => {
         // -senha para não aparecer no postman
        const user = await User.findById(id, "-senha");

        return user;
    },

    findByEmail: async (email) => {
        const userExist = await User.findOne({ email: email })
        return userExist;
    },

    findAllUsers: async() => {
        const users = await User.find({}, "-senha")
        return users;
    },

    checkPassword: async (password, passFound) => {
        const checkSenha = await bcrypt.compare(String(password), passFound)
        return checkSenha
    },

    generateHash: async (password) => {
        console.log(password)
        const hash = await bcrypt.genSalt(15)
        const senhaHash = await bcrypt.hash(String(password), hash)
        return senhaHash;
    }

}

export default UserService;