const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const stripe = require('stripe')(
  process.env.STRIPE_SECRET_KEY || 'sk_test_mock_secret_key_ticket_bari',
);

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

const jwt = require('jsonwebtoken');

// Global JWT Verification Middleware
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: 'Unauthorized access!' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({ message: 'Forbidden access!' });
    }
    req.decoded = decoded;
    next();
  });
}

async function run() {
  try {
    await client.connect();
    console.log('🎯 System Core Successfully connected to MongoDB!');

    const db = client.db('ticketBariDB');
    const ticketsCollection = db.collection('tickets');
    const usersCollection = db.collection('users');
    const bookingsCollection = db.collection('bookings');
    const transactionsCollection = db.collection('transactions');

    const bcrypt = require('bcryptjs');

    // Role Verification Middleware
    const verifyAdmin = async (req, res, next) => {
      const requesterAccount = await usersCollection.findOne({
        email: req.decoded.email,
      });
      if (requesterAccount?.role !== 'admin') {
        return res
          .status(403)
          .send({ message: 'Forbidden access! Admin privilege required.' });
      }
      next();
    };

    // ------------------------------------------------------------------------
    // BETTERAUTH & SOCIAL LOGIN ENDPOINTS (Requirement 2)
    // ------------------------------------------------------------------------
    app.post('/auth/social-sync', async (req, res) => {
      try {
        const { name, email, photoURL } = req.body;

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const newUser = {
            name,
            email,
            role: 'user',
            isFraud: false,
            photoURL: photoURL || '',
            createdAt: new Date(),
          };
          const result = await usersCollection.insertOne(newUser);
          user = { ...newUser, _id: result.insertedId };
        }

        if (user.isFraud) {
          return res.status(403).send({
            message: 'Access Denied! This profile has been flagged as fraud.',
          });
        }

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' },
        );

        res.send({
          success: true,
          token,
          user: { name: user.name, email: user.email, role: user.role },
        });
      } catch (error) {
        res.status(500).send({
          message: 'BetterAuth social token synchronization failed.',
          error,
        });
      }
    });

    // Traditional Native Authentication Endpoints
    app.post('/register', async (req, res) => {
      try {
        const { name, email, password, role } = req.body;
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).send({ message: 'Email already registered!' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: role || 'user',
          isFraud: false,
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Registration failed', error });
      }
    });

    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found!' });
        if (user.isFraud)
          return res.status(403).send({
            message: 'Access Denied! This profile has been flagged as fraud.',
          });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
          return res.status(401).send({ message: 'Invalid credentials!' });

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' },
        );
        res.send({
          success: true,
          token,
          user: { name: user.name, email: user.email, role: user.role },
        });
      } catch (error) {
        res.status(500).send({ message: 'Login failed', error });
      }
    });

    // ------------------------------------------------------------------------
    // STRIPE PAYMENT OPERATIONS & SEAT REDUCTION CORRECTION
    // ------------------------------------------------------------------------
    app.post('/create-payment-intent', verifyJWT, async (req, res) => {
      try {
        const { price } = req.body;
        if (!price || isNaN(price)) {
          return res
            .status(400)
            .send({ message: 'Invalid tokenized amount parameters.' });
        }
        const amount = Math.round(Number(price) * 100);

        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount,
          currency: 'bdt',
          payment_method_types: ['card'],
        });

        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({
          message: 'Stripe context integration crash.',
          error: error.message,
        });
      }
    });

    app.post('/payments/confirm', verifyJWT, async (req, res) => {
      try {
        const {
          bookingId,
          transactionId,
          ticketId,
          finalPrice,
          ticketTitle,
          userEmail,
          quantity, // 🎯 FETCHED: Reading user selected reservation seats metric dynamically
        } = req.body;

        const transactionRecord = {
          transactionId,
          amount: finalPrice,
          ticketTitle: ticketTitle || 'Express Fleet Access Ticket',
          paymentDate: new Date(),
          userEmail,
        };
        await transactionsCollection.insertOne(transactionRecord);

        await bookingsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          { $set: { status: 'paid' } },
        );

        const query = ObjectId.isValid(ticketId)
          ? { _id: new ObjectId(ticketId) }
          : { id: Number(ticketId) };

        // 🎯 FIXED BUG: Reduce the dynamic quantities requested by user rather than fixed -1 limit
        const seatsToReduce = quantity ? -Math.abs(Number(quantity)) : -1;
        await ticketsCollection.updateOne(query, {
          $inc: { seats: seatsToReduce },
        });

        res.send({ success: true, message: 'Transaction logs settled.' });
      } catch (error) {
        res.status(500).send({
          message: 'Failed to synchronize transaction blocks.',
          error,
        });
      }
    });

    app.get('/transactions', verifyJWT, async (req, res) => {
      const { email } = req.query;
      let query = {};
      if (email) query.userEmail = email;
      const result = await transactionsCollection
        .find(query)
        .sort({ paymentDate: -1 })
        .toArray();
      res.send(result);
    });

    // ------------------------------------------------------------------------
    // TICKETS OPERATIONS
    // ------------------------------------------------------------------------
    app.get('/tickets/advertised', async (req, res) => {
      try {
        const query = {
          isAdvertised: true,
          verificationStatus: 'approved',
          isHidden: { $ne: true },
        };
        const result = await ticketsCollection.find(query).limit(6).toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading advertisements', error });
      }
    });

    app.get('/tickets/latest', async (req, res) => {
      try {
        const query = {
          verificationStatus: 'approved',
          isHidden: { $ne: true },
        };
        const result = await ticketsCollection
          .find(query)
          .sort({ _id: -1 })
          .limit(8)
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error loading feed', error });
      }
    });

    app.get('/tickets', async (req, res) => {
      try {
        const { from, to, type, sortBy, page = 1, limit = 6 } = req.query;
        let query = { verificationStatus: 'approved', isHidden: { $ne: true } };

        if (from) query.from = { $regex: from, $options: 'i' };
        if (to) query.to = { $regex: to, $options: 'i' };
        if (type && type !== 'All Types') query.type = type;

        let sortOptions = {};
        if (sortBy === 'Price: Low to High') sortOptions.price = 1;
        else if (sortBy === 'Price: High to Low') sortOptions.price = -1;

        const skip = (Number(page) - 1) * Number(limit);
        const result = await ticketsCollection
          .find(query)
          .sort(sortOptions)
          .skip(skip)
          .limit(Number(limit))
          .toArray();
        const total = await ticketsCollection.countDocuments(query);

        res.send({ tickets: result, total, pages: Math.ceil(total / limit) });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error fetching ticket inventory', error });
      }
    });

    app.get('/tickets/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = ObjectId.isValid(id)
          ? { _id: new ObjectId(id) }
          : { id: Number(id) };
        const result = await ticketsCollection.findOne(query);
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading ticket metrics', error });
      }
    });

    app.post('/tickets', verifyJWT, async (req, res) => {
      try {
        const ticketData = req.body;
        const newFleet = {
          ...ticketData,
          price: Number(ticketData.price),
          seats: Number(ticketData.seats),
          verificationStatus: 'pending',
          isAdvertised: false,
          createdAt: new Date(),
        };
        const result = await ticketsCollection.insertOne(newFleet);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error processing vendor item creation', error });
      }
    });

    // ------------------------------------------------------------------------
    // ADMIN ACTIONS WITH STRICT GATEKEEPING
    // ------------------------------------------------------------------------
    app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection
        .find({}, { projection: { password: 0 } })
        .toArray();
      res.send(result);
    });

    app.patch('/users/role/:id', verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body;
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role } },
      );
      res.send(result);
    });

    app.patch('/users/fraud/:id', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const vendor = await usersCollection.findOne({ _id: new ObjectId(id) });
        await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isFraud: true } },
        );
        await ticketsCollection.updateMany(
          { vendorEmail: vendor.email },
          { $set: { isHidden: true } },
        );
        res.send({
          success: true,
          message: 'Vendor flagged as fraud and fleets hidden.',
        });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Fraud operation processing error.', error });
      }
    });

    app.patch(
      '/tickets/status/:id',
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { status } = req.body;
        const result = await ticketsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { verificationStatus: status } },
        );
        res.send(result);
      },
    );

    app.patch(
      '/tickets/advertise/:id',
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { advertiseState } = req.body;

        if (advertiseState === true) {
          const activeAdsCount = await ticketsCollection.countDocuments({
            isAdvertised: true,
          });
          if (activeAdsCount >= 6) {
            return res.status(400).send({
              message:
                'Maximum limit reached! Admin cannot advertise more than 6 tickets at a time.',
            });
          }
        }

        const result = await ticketsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isAdvertised: advertiseState } },
        );
        res.send({ success: true, result });
      },
    );

    // ------------------------------------------------------------------------
    // SECURED BOOKING OPERATIONS
    // ------------------------------------------------------------------------
    app.post('/bookings', verifyJWT, async (req, res) => {
      try {
        const bookingData = req.body;
        bookingData.createdAt = new Date();
        const result = await bookingsCollection.insertOne(bookingData);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Booking processing error', error });
      }
    });

    app.get('/bookings', verifyJWT, async (req, res) => {
      const email = req.query.email;
      const userRole = req.decoded.role;

      let query = {};

      // 🎯 SECURED: Allow Global bookings stream view only to Admin panel contexts
      if (userRole !== 'admin') {
        if (email && email === req.decoded.email) {
          query.userEmail = email;
        } else {
          query.userEmail = req.decoded.email; // Fallback context layer protection
        }
      } else if (email) {
        query.userEmail = email;
      }

      const result = await bookingsCollection.find(query).toArray();
      res.send(result);
    });

    app.delete('/bookings/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const result = await bookingsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });
  } finally {
    // Connection persistent block
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('TicketBari Enterprise Server running cleanly...');
});

app.listen(port, () => {
  console.log(`🚀 TicketBari Server operating securely on port ${port}`);
});
