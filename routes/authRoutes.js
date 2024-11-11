const express = require('express');
const { register, login, forgotPassword, resetPassword, verifyOtp} = require('../controllers/authControllers');
const { body, validationResult } = require('express-validator');

const router = express.Router();

const validateRegister = [
  body('name')
    .isString()
    .notEmpty()
    .withMessage('Name is required')
    .trim()
    .escape(),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('dateOfBirth')
    .isDate()
    .withMessage('Please provide a valid date of birth'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
];



router.post('/register',  register);
router.post('/forgot-password', forgotPassword);
router.post('/verify-otp', verifyOtp)
router.post('/reset-password', resetPassword);

router.post('/login', login);

module.exports = router;