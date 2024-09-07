var express = require('express');
var router = express.Router();
var AuthController = require(`../controllers/AuthController`)
router.get('/',(req,res)=>{
    res.send({signup:{path:"api/auth/signup",body:[`name`,`email`,`password`]},
                login:{path:"api/auth/login",body:[`email`,`password`]}})
})
router.post('/signup', AuthController.signup);

router.post('/login', AuthController.login);

router.get('/refresh', AuthController.refreshToken);

router.get('/logout', AuthController.logout);


module.exports = router;
