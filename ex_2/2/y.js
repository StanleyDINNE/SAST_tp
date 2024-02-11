const express = require('express');
const router = express.Router()
const xss = require("xss"); // Import du sanitizer

// pas réussi à setup les règles dans "./semgrep_sanitizer.yml" pour l'accepter
const escapeHTML = str => str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
}[tag]));

router.get("/tstMe", (req, res) => {
    var r = /[a-z]+$/; // Simplification de la RegEx

    let match = r.test(xss(req.params.id)); // Utilisation du sanitizer
    res.send(match);
});


module.exports = router
