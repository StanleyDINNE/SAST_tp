const express = require('express')
const router = express.Router()
import DOMPurify from 'dompurify';
const xss = require("xss");


router.get('/greeting', (req, res) => {
    const { name } = req.query;
    res.send('<h1> Hello :' + xss(DOMPurify.sanitize(name)) + "</h1>"); // Dompurify + sanitizing
})

router.get('/greet-template', (req, res) => {
    name = req.query.name
    res.render('index', { user_name: name });
})

module.exports = router
