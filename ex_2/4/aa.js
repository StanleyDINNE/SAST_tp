
console.log('WIP')
const express = require('express');
const router = express.Router()
import DOMPurify from 'dompurify';
const xss = require("xss");

router.get('/login', function (req, res) {
    let followPath = req.query.path;
    if (req.session.isAuthenticated()) {
        res.redirect('http://example.com/' + followPath); //false positive
    } else {
        res.redirect('/');
    }
});

router.get('/goto', function (req, res) {
    let url = xss(DOMPurify.sanitize(encodeURI(req.query.url))); // L'URL fournie via le paramètre de requête

    // Affiche une page de confirmation à l'utilisateur
    res.send(`
        <html>
        <head>
            <title>Confirmation</title>
            <script>
                function redirectToExternal(url) {
                    // Redirige l'utilisateur vers l'URL externe
                    window.location.href = url;
                }
            </script>
        </head>
        <body>
            <h1>Confirmation</h1>
            <p>Vous êtes sur le point d'être redirigé vers un site externe.</p>
            <p>Êtes-vous sûr de vouloir continuer ?</p>
            <button onclick="redirectToExternal('${url}')">Continuer</button>
            <button onclick="history.back()">Annuler</button>
        </body>
        </html>
    `);
});

module.exports = router
