import express from 'express'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import User from './models/userModel.js'


dotenv.config()
const db = process.env.DB_MONGO
const app = express()
app.use(express.json())
const PORT = 3333


app.get('/', (req, res)=>{
    res.status(200).json({msg: "WelCome to our API"})
});

app.get("/user/:id", checkToken, async (req, res) =>{
    const id = req.params.id

    try {
        // -senha para não aparecer no postman
        const user = await User.findById(id, "-senha");

        if(!user) {
            return res.status(404).json({ msg: "Usuário não encontrado" });
        }
        res.status(200).json(user);
    } catch (error) {
        return res.status(500).json({ msg: "Erro ao buscar usuário"});
    }
})


app.post('/auth/registro', async (req, res) =>{
    const {nome, idade, email, senha, confirmasenha} = req.body

    if (!nome){
        return res.status(400).json({mgs: "O nome é obrigatório"})
    }
    if (!idade || idade > 105){
        return res.status(400).json({mgs: "Erro na idade"})
    }
    if (!email){
        return res.status(400).json({mgs: "O E-mail é obrigatório"})
    }
    if (!senha){
        return res.status(400).json({mgs: "A senha é obrigatório"})
    }
    if(senha != confirmasenha){
        return res.status(400).json({mgs: 'A senha devem ser a mesma'})
    }

    const userExiste = await User.findOne({email: email})
    if(userExiste){
        return res.status(400).json({mgs: "O E-mail ja existe"})
    }

    const hash = await bcrypt.genSalt(15)
    const senhaHash = await bcrypt.hash(senha, hash)


    const user = User({
        nome,
        idade,
        email,
        senha: senhaHash,
    });

    try
    {
        await user.save()
        res.status(201).json({msg: "Usuário criado com sucesso"})
    } catch (e){
        console.log(e)
        res.status(500).json({msg: "Erro no servidor, tente mais tarde!"})
    }
});

app.post("/auth/login", async (req, res) =>{
    const {email, senha} = req.body;

    if (!email){
        return res.status(400).json({mgs: "O email é obrigatório"})
    }
    
    if (!senha){
        return res.status(400).json({mgs: "A senha é obrigatório"})
    }
    const userExiste = await User.findOne({email: email})
    
    if(!userExiste){
        return res.status(404).json({mgs: "O Usuário não foi encontrado"})
    }

    const checkSenha = await bcrypt.compare(senha, userExiste.senha)

    if(!checkSenha){
        return res.status(404).json({msg: "Senha Inválida"})
    }

    try{
        const secret = process.env.SECRET
        console.log(secret)

        const token = jwt.sign(
            {
            id: userExiste._id
            },
            secret,
        )
        res.status(200).json({msg: "Autenticação realizada com sucesso", token})
    }catch (e){
        console.log(e)
        res.status(500).json({msg: "Erro no servidor, tente mais tarde!"})
    }
})


function checkToken(req, res, next){
    const header = req.headers['authorization']
    const token = header.split(" ")[1]
    console.log(token)
    if(!token){
        return res.status(401).json({msg: "Acesso negado"})
    }
    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()

    }catch (e){
        return res.status(400).json({msg: "Token inválido"})
    }
}



app.listen(
    PORT,
    mongoose.connect(`mongodb://localhost:27017/${db}`).then(() => console.log('connected'))
)