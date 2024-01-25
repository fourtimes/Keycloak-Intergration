var express = require('express');
var router = express.Router();
const keycloak = require('../config/keycloak-config.js').getKeycloak();

router.get('/anonymous', function (req, res) {
    res.send("Hello Anonymous");
});

router.post('/us', (req, res) => {
    const {grant_type, client_id, client_secret, username, password} = req.body;
    console.log(client_id);

});
router.get('/user', keycloak.protect('user'), (req, res) => {
    console.log(res)
    res.send("This is the Keycloak employee1 user with User Role ");
});

router.get('/admin', keycloak.protect('admin'), (req, res) => {
    res.send("This is the Keycloak employee2 user with Admin Role");
});

router.get('/all-user', keycloak.protect(['user', 'admin']), (req, res) => {
    res.send("This is the Keycloak employee3 user with User & Admin Role");
});

module.exports = router;

// http://localhost:8080/auth/realms/Demo-Realm/protocol/openid-connect/token