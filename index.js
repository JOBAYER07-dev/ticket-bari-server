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

    const bcrypt = require('bcryptjs');

    // ------------------------------------------------------------------------
    // Role Verification Middlewares
    // ------------------------------------------------------------------------
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
    // AUTHENTICATION ENDPOINTS
    // ------------------------------------------------------------------------
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
          isFraud: false, // Core requirement 8c
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
    // TICKETS OPERATIONS (USER, VENDOR, ADMIN)
    // ------------------------------------------------------------------------

    // Get Tickets with Filters, Sort, and Paginated Parameters
    app.get('/tickets', async (req, res) => {
      try {
        const { from, to, type, sortBy, page = 1, limit = 6 } = req.query;

        // Dynamic search query constraint
        // Requirement 4 & 8c: Only show admin-approved tickets AND filter out fraud vendors
        let query = { verificationStatus: 'approved', isHidden: { $ne: true } };

        if (from) query.from = { $regex: from, $options: 'i' };
        if (to) query.to = { $regex: to, $options: 'i' };
        if (type && type !== 'All Types') query.type = type;

        let sortOptions = {};
        if (sortBy === 'Price: Low to High') sortOptions.price = 1;
        else if (sortBy === 'Price: High to Low') sortOptions.price = -1;

        // Challenge Requirement 4: Pagination Implementation
        const skip = (Number(page) - 1) * Number(limit);
        const cursor = ticketsCollection
          .find(query)
          .sort(sortOptions)
          .skip(skip)
          .limit(Number(limit));
        const result = await cursor.toArray();
        const total = await ticketsCollection.countDocuments(query);

        res.send({ tickets: result, total, pages: Math.ceil(total / limit) });
      } catch (error) {
        res.status(500).send({ message: 'Error fetching tickets', error });
      }
    });

    // Dynamic Single Ticket Details Dynamic API
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
          .send({ message: 'Error fetching ticket details', error });
      }
    });

    // Vendor Adds New Ticket (Initially Pending Verification Status)
    app.post('/tickets', verifyJWT, async (req, res) => {
      try {
        const ticketData = req.body;
        const newFleet = {
          ...ticketData,
          price: Number(ticketData.price),
          seats: Number(ticketData.seats),
          verificationStatus: 'pending', // Requirement 7b
          isAdvertised: false,
          createdAt: new Date(),
        };
        const result = await ticketsCollection.insertOne(newFleet);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error processing vendor listing', error });
      }
    });

    // ------------------------------------------------------------------------
    // CORE ADMIN CONSOLE ACTIONS (Requirement 8)
    // ------------------------------------------------------------------------

    // Get All App Users
    app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection
        .find({}, { projection: { password: 0 } })
        .toArray();
      res.send(result);
    });

    // Admin Changes Role (Make Admin / Make Vendor)
    app.patch('/users/role/:id', verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body;
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role } },
      );
      res.send(result);
    });

    // Admin Marks Vendor as Fraud (Requirement 8c)
    app.patch('/users/fraud/:id', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const vendor = await usersCollection.findOne({ _id: new ObjectId(id) });

        // 1. Mark vendor profile as fraud
        await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isFraud: true } },
        );

        // 2. Hide all existing tickets published by this specific fraud vendor email
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
          .send({ message: 'Fraud transaction processing aborted', error });
      }
    });

    // Admin Approves/Rejects Vendor Ticket (Requirement 8b)
    app.patch(
      '/tickets/status/:id',
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { status } = req.body; // status can be 'approved' or 'rejected'
        const result = await ticketsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { verificationStatus: status } },
        );
        res.send(result);
      },
    );

    // Admin Toggles Advertisement State (Requirement 8d)
    app.patch(
      '/tickets/advertise/:id',
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { advertiseState } = req.body; // true or false

        if (advertiseState === true) {
          const activeAdsCount = await ticketsCollection.countDocuments({
            isAdvertised: true,
          });
          if (activeAdsCount >= 6) {
            return res
              .status(400)
              .send({
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
    // BOOKING OPERATIONS
    // ------------------------------------------------------------------------
    app.post('/bookings', verifyJWT, async (req, res) => {
      try {
        const bookingData = req.body;
        bookingData.createdAt = new Date();
        const result = await bookingsCollection.insertOne(bookingData);
        res
          .status(201)
          .send({
            success: true,
            message: 'Saved with Pending status',
            insertId: result.insertedId,
          });
      } catch (error) {
        res.status(500).send({ message: 'Booking processing error', error });
      }
    });

    app.get('/bookings', verifyJWT, async (req, res) => {
      const email = req.query.email;
      let query = {};
      if (email) query.userEmail = email; // If email is passed, filter for user. If empty, master log for admin.
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
    // Keep alive connection pool
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('TicketBari Enterprise Server running cleanly...');
});

app.listen(port, () => {
  console.log(`🚀 TicketBari Server operating securely on port ${port}`);
});
