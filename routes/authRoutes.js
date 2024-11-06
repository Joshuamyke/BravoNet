const express = require('express');
const { register, login, requestPasswordReset, resetPassword } = require('../controllers/authController');
const { body } = require('express-validator');

const router = express.Router();

router.post(
    '/register',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
        body('email').isEmail().withMessage('Valid email is required'),
    ],
    register
);

router.post('/request-password-reset', requestPasswordReset);
router.post('/reset-password', resetPassword);
router.post('/login', login);

module.exports = router;