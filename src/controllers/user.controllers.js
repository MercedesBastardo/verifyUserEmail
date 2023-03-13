const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmails.js');
const EmailCode = require('../models/EmailCode');
const jwt= require('jsonwebtoken')

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, lastName, country, image, frontBaseUrl} = req.body;
    const encriptedPassword= await bcrypt.hash(password,10);

    const result = await User.create({email, password: encriptedPassword, firstName, lastName, country, image});

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/verify_email/${code}`;

    await sendEmail({
        to: email,
        subject:"User app email verification",
        html:`
            <h1>Hello ${firstName}!</h1>
            <p> Were almost done</p>
            <p> Go to the following link to verify your mail </p>
            <a href="${link}"> ${link} </a>
            `
    });

    await EmailCode.create({code, userId: result.id});

    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyEmail = catchError(async(req,res) => {
    const {code } =req.params;
    const emailCode= await EmailCode.findOne({where : {code}});
    if(!emailCode) return res.status(401).json({message:"Invalided Code"});

    await User.update(
        {isVerified: true},
        {where: {id: emailCode.userId}}
    );

    await emailCode.destroy();

    return res.json(emailCode)
})

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: {email} });
    if(!user) return res.status(401).json({ error: "invalid credentials" });
    if(!user.isVerified) return res.status(401).json({ error: "invalid credentials" });
    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({ error: "invalid credentials" });


    const token = jwt.sign(
            {user},
            process.env.TOKEN_SECRET,
            { expiresIn: '3d' }
    )

    return res.json({user, token});
})

const getLoggetUser = catchError(async(req,res) => {
    const user= req.user;

    return res.json(user)
});

// const resetPassword = catchError(async(req,res) => {
//     const {email, frontBaseUrl} = req.body;
//     const user = await User.findOne({ where: {email} });
//     const link = `${frontBaseUrl}/reset_password/:code`;
//     if (user) {
//         await sendEmail({
//             to: email,
//             subject:"User app email verification",
//             html:`
//                 <h1>Hello ${user.firstName}</h1>
//                 <p> Change your password</p>
//                 <a href="${link}"> ${link} </a>
               
//                 `
//         });
//     } 
//     return res.status(201).json(user);

// });

// const changePassword = catchError(async(req,res) => {
//     const {password, confirmPassword} = req.body;
//     const user= req.user;
//         if(password===confirmPassword){
//             const encriptedPassword= await bcrypt.hash(password,10);
//             const result = await user.update(
//             {email, password: encriptedPassword, firstName, lastName, country, image}, 
//             { where: {id}, returning: true });
//             return res.status(201).json(result[1][0]);
//         } else{
//     return res.status(401).json({message:"not coincident"});
// }
// });


module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    getLoggetUser,
    // resetPassword, changePassword
}