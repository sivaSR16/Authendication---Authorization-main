const User = require("../models/users");
const bcrypt = require("bcryptjs"); // ✅ use bcryptjs instead of bcrypt
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../utils/config");

const authController = {
  // register
  register: async (request, response) => {
    try {
      const { name, email, password } = request.body;

      // check if the user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return response.status(400).json({ message: "user already exists" });
      }

      // encrypt the password
      const PasswordHash = await bcrypt.hash(password, 10);

      const newUser = new User({
        name,
        email,
        password: PasswordHash,
      });

      await newUser.save();
      response.json({ message: "user registered successfully" });
    } catch (error) {
      response.status(500).json({ message: error.message });
    }
  },

  // login
  login: async (request, response) => {
    try {
      const { email, password } = request.body;

      const user = await User.findOne({ email });
      if (!user) {
        return response.status(400).json({ message: "user does not exist" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return response.status(400).json({ message: "invalid password" });
      }

      const token = await jwt.sign(
        { id: user._id },
        SECRET_KEY,
        { expiresIn: "1h" } // optional: set expiry for better security
      );

      response.json({ token, message: "user logged in successfully" });
    } catch (error) {
      response.status(500).json({ message: error.message });
    }
  },

  // profile
  me: async (request, response) => {
    try {
      const userId = request.userId;
      const user = await User.findById(userId).select(
        "-password -createdAt -updatedAt"
      );

      response.json(user);
    } catch (error) {
      response.status(500).json({ message: error.message });
    }
  },
};

module.exports = authController;
