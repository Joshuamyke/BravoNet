const express = require('express');
const { register, login, requestPasswordReset, resetPassword } = require('../controllers/authControllers');
const { body, validationResult } = require('express-validator');

const router = express.Router();

router.post('/register', [
    // Validate and sanitize inputs
    body('name').isString().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Please provide a valid email address'),
    body('dateOfBirth').isDate().withMessage('Please provide a valid date of birth'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    try {
        // Handle validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        // Call the register controller function
        const { name, email, dateOfBirth, password } = req.body;
        const user = await register({ name, email, dateOfBirth, password });

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                name: user.name,
                email: user.email,
                dateOfBirth: user.dateOfBirth,
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/request-password-reset', requestPasswordReset);
router.post('/reset-password', resetPassword);
router.post('/login', login);

module.exports = router;