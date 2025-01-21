require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log('Connected to MongoDB Atlas');
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB Atlas:', err);
  });

// Mongoose Schema and Model for users
const usersSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { versionKey: false });

const Users = mongoose.model('Users', usersSchema);

// Mongoose Schema and Model for restaurants
const restaurantSchema = new mongoose.Schema({
  address: {
    building: String,
    street: String,
    zipcode: String
  },
  borough: String,
  cuisine: String,
  grades: [
    {
      date: Date,
      grade: String,
      score: Number
    }
  ],
  name: String,
  restaurant_id: String
}, { versionKey: false });

const Restaurant = mongoose.model('Restaurant', restaurantSchema);

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
  if (!token) {
    return res.status(403).json({ error: 'Token is required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;  // Save the decoded user info in request
    next();
  });
};

// Sign-up Route: Register a new user
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  // Check if email already exists
  const existingUser = await Users.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ error: 'Email already in use' });
  }

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);  // Salt rounds set to 10

  // Create and save the new user
  const newUser = new Users({ email, password: hashedPassword });

  try {
    await newUser.save();
    res.status(201).json({ message: 'User successfully registered' });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user', details: err.message });
  }
});

// LOGIN: Authenticate user and issue JWT
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = await Users.findOne({ email });
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Compare provided password with stored password (hash)
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Create JWT token
  const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
  // Return token to the client
  res.json({ token });
});

// LOGOUT: Logout the user
app.post('/logout', (req, res) => {
  // Simply return a success message to indicate that the client can remove the token
  res.json({ message: 'User logged out successfully' });
});

// SEARCH: Search for restaurants
app.get('/restaurants/search', authenticateToken, async (req, res) => {
  try {
    // Extract query parameters
    const { name, cuisine } = req.query;

    // Build a query object dynamically
    const query = {};

    if (name) {
      query.name = { $regex: name, $options: 'i' };  // Case-insensitive regex search for name
    }
    if (cuisine) {
      query.cuisine = { $regex: cuisine, $options: 'i' };  // Case-insensitive regex search for cuisine
    }

    // Perform the search using the query object
    const restaurants = await Restaurant.find(query);

    // Return the search results
    if (restaurants.length === 0) {
      return res.status(404).json({ message: 'No restaurants found matching the search criteria' });
    }

    res.json(restaurants);
  } catch (err) {
    res.status(500).json({ error: 'Error searching for restaurants', details: err.message });
  }
});

// CREATE: Add a new restaurant
app.post('/restaurants', authenticateToken, async (req, res) => {
  try {
    const newRestaurant = new Restaurant(req.body);
    const savedRestaurant = await newRestaurant.save();
    res.status(201).json(savedRestaurant);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// READ: Get all restaurants
app.get('/restaurants', authenticateToken, async (req, res) => {
  try {
    const restaurants = await Restaurant.find();
    res.json(restaurants);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// READ: Get a single restaurant by ID
app.get('/restaurants/:id', authenticateToken, async (req, res) => {
  try {
    const restaurant = await Restaurant.findById(req.params.id);
    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant not found' });
    }
    res.json(restaurant);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE: Update a restaurant by ID
app.put('/restaurants/:id', authenticateToken, async (req, res) => {
  try {
    const updatedRestaurant = await Restaurant.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedRestaurant) {
      return res.status(404).json({ error: 'Restaurant not found' });
    }
    res.json(updatedRestaurant);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE: Delete a restaurant by ID
app.delete('/restaurants/:id', authenticateToken, async (req, res) => {
  try {
    const deletedRestaurant = await Restaurant.findByIdAndDelete(req.params.id);
    if (!deletedRestaurant) {
      return res.status(404).json({ error: 'Restaurant not found' });
    }
    res.json({ message: 'Restaurant deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE: Remove a user (authenticated route)
app.delete('/users/me', authenticateToken, async (req, res) => {
  try {
    // The user ID is extracted from the decoded token (req.user contains the user information)
    const userId = req.user.userId;

    // Delete the user from the database
    const deletedUser = await Users.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error deleting user', details: err.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
