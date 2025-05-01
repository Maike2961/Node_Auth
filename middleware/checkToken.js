import jwt from 'jsonwebtoken'

const checkToken = (req, res, next) => {
    try {
        const header = req.headers['authorization']

        if (header != null) {
            const token = header.split(" ")[1]

            if (!token) {
                return res.status(401).json({ msg: "Acesso negado" })
            }
            const secret = process.env.SECRET
            jwt.verify(token, secret)
            next()
        }else{
            return res.status(401).json({ msg: "Acesso negado" })
        }
    } catch (e) {
        return res.status(400).json({ msg: "Token inválido" })
    }
}

export default checkToken;