const registerController = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
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
  };