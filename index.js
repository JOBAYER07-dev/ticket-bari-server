const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware configuration
app.use(cors());
app.use(express.json());

// MongoDB connection configuration
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ------------------------------------------------------------------------
// 7. JWT Token Verification Middleware (Commit 7)
// ------------------------------------------------------------------------
const jwt = require('jsonwebtoken');

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .send({ message: 'Unauthorized access! Missing token.' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .send({ message: 'Forbidden access! Invalid token.' });
    }
    req.decoded = decoded;
    next();
  });
}

async function run() {
  try {
    // Connect to MongoDB Atlas
    await client.connect();
    console.log('🎯 Successfully connected to MongoDB!');

    const db = client.db('ticketBariDB');
    const ticketsCollection = db.collection('tickets');
    const usersCollection = db.collection('users');
    const bookingsCollection = db.collection('bookings');

    const bcrypt = require('bcryptjs');

    // ------------------------------------------------------------------------
    // 3. User Registration API (Commit 3)
    // ------------------------------------------------------------------------
    app.post('/register', async (req, res) => {
      try {
        const { name, email, password, role } = req.body;

        // Check if the user email already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res
            .status(400)
            .send({ message: 'Email is already registered!' });
        }

        // Secure password hashing
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Prepare new user object
        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: role || 'user',
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({
          success: true,
          message: 'User registered successfully!',
          insertId: result.insertedId,
        });
      } catch (error) {
        res.status(500).send({
          message: 'Internal server error during registration',
          error,
        });
      }
    });

    // ------------------------------------------------------------------------
    // 4. User Login & JWT Generation API (Commit 4)
    // ------------------------------------------------------------------------
    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        // Verify if user exists
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res
            .status(404)
            .send({ message: 'User not found! Please register first.' });
        }

        // Compare password with hashed password
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
          return res
            .status(401)
            .send({ message: 'Invalid email or password!' });
        }

        // Generate JWT Token payload
        const tokenPayload = {
          uid: user._id,
          email: user.email,
          role: user.role,
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
          expiresIn: '7d',
        });

        res.status(200).send({
          success: true,
          message: 'Login successful!',
          token,
          user: {
            name: user.name,
            email: user.email,
            role: user.role,
          },
        });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Internal server error during login', error });
      }
    });

    // ------------------------------------------------------------------------
    // 1. Basic Server Health Check Route 
    // ------------------------------------------------------------------------
    app.get('/', (req, res) => {
      res.send('TicketBari Server is running smoothly...');
    });

    // ------------------------------------------------------------------------
    // 5. Get All Tickets API with Search, Filter & Sort 
    // ------------------------------------------------------------------------
    app.get('/tickets', async (req, res) => {
      try {
        const { from, to, type, sortBy } = req.query;
        let query = {};

        // Case-insensitive search filters
        if (from) {
          query.from = { $regex: from, $options: 'i' };
        }
        if (to) {
          query.to = { $regex: to, $options: 'i' };
        }
        if (type && type !== 'All Types') {
          query.type = type;
        }

        // Price sorting configuration
        let sortOptions = {};
        if (sortBy === 'Price: Low to High') {
          sortOptions.price = 1;
        } else if (sortBy === 'Price: High to Low') {
          sortOptions.price = -1;
        }

        const cursor = ticketsCollection.find(query).sort(sortOptions);
        const result = await cursor.toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching tickets', error });
      }
    });

    // ------------------------------------------------------------------------
    // 6. Get Single Ticket Details Dynamic API 
    // ------------------------------------------------------------------------
    app.get('/tickets/:id', async (req, res) => {
      try {
        const id = req.params.id;

        let query;
        if (ObjectId.isValid(id)) {
          query = { _id: new ObjectId(id) };
        } else {
          query = { id: Number(id) };
        }

        const result = await ticketsCollection.findOne(query);

        if (!result) {
          return res.status(404).send({ message: 'Ticket not found!' });
        }

        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error fetching ticket details', error });
      }
    });

    // ------------------------------------------------------------------------
    // 8. Create Ticket Booking API - Protected Route 
    // ------------------------------------------------------------------------
    app.post('/bookings', verifyJWT, async (req, res) => {
      try {
        const bookingData = req.body;

        // Security check: Verify token owner matches requester email
        if (req.decoded.email !== bookingData.userEmail) {
          return res
            .status(403)
            .send({ message: 'Forbidden access! Token mismatch.' });
        }

        bookingData.createdAt = new Date();
        const result = await bookingsCollection.insertOne(bookingData);

        res.status(201).send({
          success: true,
          message: 'Ticket booked successfully!',
          bookingId: result.insertedId,
        });
      } catch (error) {
        res.status(500).send({ message: 'Error processing booking', error });
      }
    });

    // ------------------------------------------------------------------------
    // 9. Get Specific User's Bookings API - Protected Route 
    // ------------------------------------------------------------------------
    app.get('/bookings', verifyJWT, async (req, res) => {
      try {
        const email = req.query.email;

        // Security check: Verify token email matches the requested query email
        if (req.decoded.email !== email) {
          return res.status(403).send({ message: 'Forbidden access!' });
        }

        const query = { userEmail: email };
        const result = await bookingsCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error fetching user bookings', error });
      }
    });

    // ------------------------------------------------------------------------
    // 10. Cancel Booking API - Protected Route 
    // ------------------------------------------------------------------------
    app.delete('/bookings/:id', verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };

        const result = await bookingsCollection.deleteOne(query);
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Booking not found!' });
        }

        res.send({ success: true, message: 'Booking canceled successfully!' });
      } catch (error) {
        res.status(500).send({ message: 'Error canceling booking', error });
      }
    });
  } finally {
    // Connection pool remains open
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`🚀 TicketBari Server is zooming on port ${port}`);
});
