import UserService from '../service/userService.js';
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose';
import dotenv from 'dotenv'

dotenv.config()

const UserController = {

    loginUser: async (req, res) => {
        const { email, senha } = req.body;

        if (!email) {
            return res.status(400).json({ mgs: "O email é obrigatório" })
        }

        if (!senha) {
            return res.status(400).json({ mgs: "A senha é obrigatório" })
        }
        const userExiste = await UserService.findByEmail(email)

        if (!userExiste) {
            return res.status(404).json({ mgs: "O Usuário não foi encontrado" })
        }

        const checkSenha = await UserService.checkPassword(senha, userExiste.senha)

        if (!checkSenha) {
            return res.status(404).json({ msg: "Senha Inválida" })
        }


        try {
            const secret = process.env.SECRET

            const token = jwt.sign(
                {
                    id: userExiste._id
                },
                secret)


            return res.status(200).json({ msg: "Autenticação realizada com sucesso", token })
        } catch (e) {
            return res.status(500).json({ msg: "Erro no servidor, tente mais tarde!" })
        }
    },

    createUser: async (req, res) => {
        const { nome, idade, email, senha, confirmasenha } = req.body;

        if (!nome) {
            return res.status(400).json({ mgs: "O nome é obrigatório" })
        }
        if (!idade || idade > 105) {
            return res.status(400).json({ mgs: "Erro na idade" })
        }
        if (!email) {
            return res.status(400).json({ mgs: "O E-mail é obrigatório" })
        }
        if (!senha) {
            return res.status(400).json({ mgs: "A senha é obrigatório" })
        }
        if (senha != confirmasenha) {
            return res.status(400).json({ mgs: 'A senha devem ser a mesma' })
        }

        try {

            const user = await UserService.findByEmailAndNome(email, nome)

            if (user) {
                return res.status(404).json({ msg: "Usuário ja existe" });
            }

            const senhaHash = await UserService.generateHash(senha)

            const usersalve = await UserService.saveUser(nome, idade, email, senhaHash)
            console.log(JSON.stringify(usersalve))

            return res.status(201).json({ msg: "Usuário criado com sucesso" })

        } catch (e) {
            console.log(e)

            return res.status(500).json({ msg: "Erro no servidor, tente mais tarde!" })
        }
    },

    getUserById: async (req, res) => {
        const id = req.params.id

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ msg: "ID inválido" });
        }

        try {
            const user = await UserService.findById(id);

            if (!user) {
                return res.status(404).json({ mgs: "O Usuário não foi encontrado" })
            }

            return res.status(200).json(user);

        } catch (error) {
            return res.status(500).json({ msg: "Erro ao buscar usuário" });
        }
    },

    listAllUsers: async (req, res) => {
        console.log("teste")
        try {
            const users = await UserService.findAllUsers()

            if (users.length === 0) {
                return res.status(404).json({ msg: "Nenhum usuário encontrado" });
            }
            return res.status(200).json(users);
        }
        catch (err) {
            console.error(error);
            return res.status(500).json({ msg: "Erro ao buscar usuários" });
        }
    },

    helloWorld: async (req, res) => {
        return res.status(200).json({ msg: "WelCome to our API" })
    }
}

export default UserController;