const { getAll, create, getOne, remove, update, verifyEmail, login, getLoggetUser, resetPassword, changePassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/login')
    .post(login)

userRouter.route('/me')
    .get(verifyJWT, getLoggetUser)

userRouter.route('/verify/:code')
    .get(verifyEmail)

// userRouter.route('/reset_password/email')
//     .post(verifyJWT, resetPassword)

// userRouter.route('/reset_password/:code')
//     .put(verifyJWT, changePassword)

userRouter.route('/:id')
    .get(verifyJWT,getOne)
    .delete(verifyJWT,remove)
    .put(verifyJWT,update);

module.exports = userRouter;