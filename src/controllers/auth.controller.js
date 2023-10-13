import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { connectDB } from "../config/db.js";
import generateToken from "../helpers/generateToken.js";
import confirmationEmail from "../helpers/confirmationEmail.js";
import forgetPasswordEmail from "../helpers/forgetPasswordEmail.js";

const register = async (req, res) => {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await connectDB.query("SELECT * FROM psychologists WHERE email = ?", [email]);
    
    if (existingUser.length) {
        return res.status(400).json({ message: "El usuario ya existe." });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = generateToken();

    // Save user in database
    await connectDB.query("INSERT INTO psychologists (name, email, password, token) VALUES (?, ?, ?, ?)", [name, email, hashedPassword, token]);
    
    // Send confirmation email
    await confirmationEmail({ name, email, token });
    
    res.status(201).json({ message: "Usuario registrado con éxito. Por favor confirma tu correo electrónico." });
};

const confirmAccount = async (req, res) => {
    const token = req.params.token;

    // Logic to verify the token and confirm the account
    const user = await connectDB.query("SELECT * FROM psychologists WHERE token = ?", [token]);

    if (user.length) {
        await connectDB.query("UPDATE psychologists SET confirmed = 1 WHERE token = ?", [token]);
        res.status(200).json({ message: "Cuenta confirmada con éxito." });
    } else {
        res.status(400).json({ message: "Token inválido o ya ha sido utilizado." });
    }
};

const login = async (req, res) => {
    const { email, password } = req.body;

    // Check if user exists and is confirmed
    const user = await connectDB.query("SELECT * FROM psychologists WHERE email = ?", [email]);

    if (user.length && user[0].confirmed && bcrypt.compareSync(password, user[0].password)) {
        const token = jwt.sign({ id: user[0].id }, "your_jwt_secret", { expiresIn: '1h' }); // You should store JWT secret in environment variables

        return res.json({ token });
    }

    res.status(400).json({ message: "Correo electrónico o contraseña incorrectos." });
};

const forgetPassword = async (req, res) => {
    const { email } = req.body;

    const user = await connectDB.query("SELECT * FROM psychologists WHERE email = ?", [email]);

    if (!user.length) {
        return res.status(400).json({ message: "Usuario no encontrado." });
    }

    const token = generateToken();

    await connectDB.query("UPDATE psychologists SET resetPasswordToken = ? WHERE email = ?", [token, email]);

    // Send email
    await forgetPasswordEmail({ name: user[0].name, email, token });

    res.json({ message: "Correo de recuperación de contraseña enviado." });
};


export { register, login, confirmAccount, forgetPassword };
