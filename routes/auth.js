const router = require('express').Router();
const User = require('../model/User');
const jwt = require('jsonwebtoken')
const { registerValidation, loginValidation } = require('../validation')
const bcrypt = require('bcrypt');
const express = require('express');

const app = express()



router.post('/register', async(req, res) => {
    // validate data before make a user
    const { error } = registerValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // checking if user already in the database
    const emailExist = await User.findOne({ email: req.body.email });
    if (emailExist) return res.status(400).send('email already exists')

    // Hashing passwords
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(req.body.password, salt)

    // create a new user
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });
    try {
        const savedUser = await user.save()
        res.send({ user: user._id })
    } catch {
        res.status(400).send(err)
    }
})


// login !
router.post('/login', async(req, res) => {
    // here i check validation of the user login
    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // checking if the email exists
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send('Email or password is incorrect');

    //  check if the password is correct 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('invalid password')

    // Create and assign a token
    const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET)
    res.header('auth-token', token).send(token + user)
    res.redirect('/')

});

module.exports = router;