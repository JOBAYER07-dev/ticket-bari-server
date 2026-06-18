const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    console.log('🎯 Successfully connected to MongoDB!');

    const db = client.db('ticketBariDB');
    const ticketsCollection = db.collection('tickets');
    const usersCollection = db.collection('users');
    const bookingsCollection = db.collection('bookings');

    const bcrypt = require('bcryptjs');

    app.post('/register', async (req, res) => {
      try {
        const { name, email, password, role } = req.body;

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res
            .status(400)
            .send({ message: 'Email is already registered!' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

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

    const jwt = require('jsonwebtoken');

    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res
            .status(404)
            .send({ message: 'User not found! Please register first.' });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
          return res
            .status(401)
            .send({ message: 'Invalid email or password!' });
        }

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

    //end

    app.get('/', (req, res) => {
      res.send('TicketBari Server is running smoothly...');
    });

    app.get('/tickets', async (req, res) => {
      try {
        const cursor = ticketsCollection.find({});
        const result = await cursor.toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching tickets', error });
      }
    });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`🚀 TicketBari Server is zooming on port ${port}`);
});
