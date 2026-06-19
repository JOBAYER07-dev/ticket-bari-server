const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// MongoDB Connection
// ─────────────────────────────────────────────
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ─────────────────────────────────────────────
// JWT Middleware
// ─────────────────────────────────────────────
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: 'Unauthorized!' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: 'Forbidden!' });
    req.decoded = decoded;
    next();
  });
}

async function run() {
  try {
    await client.connect();
    console.log('✅ Connected to MongoDB!');

    const db = client.db('ticketBariDB');
    const ticketsCollection = db.collection('tickets');
    const usersCollection = db.collection('users');
    const bookingsCollection = db.collection('bookings');
    const transactionsCollection = db.collection('transactions');

    // ── Role Middleware ──────────────────────
    const verifyAdmin = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.decoded.email });
      if (user?.role !== 'admin')
        return res.status(403).send({ message: 'Admin access required.' });
      next();
    };

    const verifyVendor = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.decoded.email });
      if (user?.role !== 'vendor' && user?.role !== 'admin')
        return res.status(403).send({ message: 'Vendor access required.' });
      next();
    };

    // ══════════════════════════════════════════
    // AUTH ENDPOINTS
    // ══════════════════════════════════════════

    // Register
    app.post('/register', async (req, res) => {
      try {
        const { name, email, password, role } = req.body;

        const existing = await usersCollection.findOne({ email });
        if (existing)
          return res.status(400).send({ message: 'Email already registered!' });

        const hashedPassword = await bcrypt.hash(password, 10);

        // ✅ Security: block admin self-registration
        const safeRole = role === 'admin' ? 'user' : role || 'user';

        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: safeRole,
          isFraud: false,
          photoURL: '',
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Registration failed', error });
      }
    });

    // Login
    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });

        if (!user) return res.status(404).send({ message: 'User not found!' });
        if (user.isFraud)
          return res.status(403).send({ message: 'Account flagged as fraud.' });

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
          user: {
            name: user.name,
            email: user.email,
            role: user.role,
            photoURL: user.photoURL || '',
          },
        });
      } catch (error) {
        res.status(500).send({ message: 'Login failed', error });
      }
    });

    // Google / Social Login Sync
    app.post('/auth/social-sync', async (req, res) => {
      try {
        const { name, email, photoURL } = req.body;
        let user = await usersCollection.findOne({ email });

        if (!user) {
          const result = await usersCollection.insertOne({
            name,
            email,
            role: 'user',
            isFraud: false,
            photoURL: photoURL || '',
            createdAt: new Date(),
          });
          user = await usersCollection.findOne({ _id: result.insertedId });
        }

        if (user.isFraud)
          return res.status(403).send({ message: 'Account flagged as fraud.' });

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' },
        );

        res.send({
          success: true,
          token,
          user: {
            name: user.name,
            email: user.email,
            role: user.role,
            photoURL: user.photoURL || '',
          },
        });
      } catch (error) {
        res.status(500).send({ message: 'Social sync failed', error });
      }
    });

    // ─── One-time Admin Seed (call once, then remove or protect) ───
    // POST /seed/admin   body: { name, email, password, secretKey }
    app.post('/seed/admin', async (req, res) => {
      try {
        const { name, email, password, secretKey } = req.body;

        // Simple secret key protection so random people can't use this
        if (secretKey !== process.env.SEED_SECRET) {
          return res.status(403).send({ message: 'Invalid seed key.' });
        }

        const existing = await usersCollection.findOne({ email });
        if (existing) {
          // If exists, just make them admin
          await usersCollection.updateOne(
            { email },
            { $set: { role: 'admin' } },
          );
          return res.send({
            success: true,
            message: 'Existing user promoted to admin.',
          });
        }

        const hashed = await bcrypt.hash(password, 10);
        await usersCollection.insertOne({
          name,
          email,
          password: hashed,
          role: 'admin',
          isFraud: false,
          photoURL: '',
          createdAt: new Date(),
        });

        res
          .status(201)
          .send({ success: true, message: 'Admin created successfully.' });
      } catch (error) {
        res.status(500).send({ message: 'Seed failed', error });
      }
    });

    // ══════════════════════════════════════════
    // TICKET ENDPOINTS
    // ⚠️ Specific routes MUST come before /:id
    // ══════════════════════════════════════════

    // Public: Advertised tickets (home page)
    app.get('/tickets/advertised', async (req, res) => {
      try {
        const result = await ticketsCollection
          .find({
            advertised: true,
            status: 'approved',
            isHidden: { $ne: true },
          })
          .limit(6)
          .toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading advertised tickets', error });
      }
    });

    // Public: Latest tickets (home page)
    app.get('/tickets/latest', async (req, res) => {
      try {
        const result = await ticketsCollection
          .find({ status: 'approved', isHidden: { $ne: true } })
          .sort({ _id: -1 })
          .limit(8)
          .toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading latest tickets', error });
      }
    });

    // Admin: ALL tickets (including pending/rejected)
    app.get('/tickets/all', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const result = await ticketsCollection
          .find({})
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error loading all tickets', error });
      }
    });

    // Vendor: Their own tickets
    app.get('/tickets/vendor', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const email = req.query.email;

        // Security: vendor can only see their own tickets
        if (req.decoded.role === 'vendor' && email !== req.decoded.email) {
          return res.status(403).send({ message: 'Forbidden.' });
        }

        const query = email
          ? { vendorEmail: email }
          : { vendorEmail: req.decoded.email };
        const result = await ticketsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error loading vendor tickets', error });
      }
    });

    // Public: All tickets with search, filter, sort, pagination
    app.get('/tickets', async (req, res) => {
      try {
        const { from, to, type, sortBy, page = 1, limit = 6 } = req.query;

        let query = { status: 'approved', isHidden: { $ne: true } };
        if (from) query.from = { $regex: from, $options: 'i' };
        if (to) query.to = { $regex: to, $options: 'i' };
        if (type && type !== 'All Types') query.type = type;

        let sortOptions = {};
        if (sortBy === 'Price: Low to High') sortOptions.price = 1;
        if (sortBy === 'Price: High to Low') sortOptions.price = -1;

        const skip = (Number(page) - 1) * Number(limit);
        const total = await ticketsCollection.countDocuments(query);
        const result = await ticketsCollection
          .find(query)
          .sort(sortOptions)
          .skip(skip)
          .limit(Number(limit))
          .toArray();

        res.send({
          tickets: result,
          total,
          pages: Math.ceil(total / Number(limit)),
        });
      } catch (error) {
        res.status(500).send({ message: 'Error fetching tickets', error });
      }
    });

    // Public: Single ticket details
    app.get('/tickets/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = ObjectId.isValid(id)
          ? { _id: new ObjectId(id) }
          : { id: Number(id) };
        const result = await ticketsCollection.findOne(query);
        if (!result)
          return res.status(404).send({ message: 'Ticket not found.' });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error loading ticket', error });
      }
    });

    // Vendor: Create ticket
    app.post('/tickets', verifyJWT, verifyVendor, async (req, res) => {
      try {
        // Check if vendor is flagged as fraud
        const vendor = await usersCollection.findOne({
          email: req.decoded.email,
        });
        if (vendor?.isFraud)
          return res
            .status(403)
            .send({ message: 'Fraud vendors cannot add tickets.' });

        const newTicket = {
          ...req.body,
          price: Number(req.body.price),
          seats: Number(req.body.seats),
          status: 'pending', // ✅ field name: status (not verificationStatus)
          advertised: false, // ✅ field name: advertised (not isAdvertised)
          isHidden: false,
          createdAt: new Date(),
        };

        const result = await ticketsCollection.insertOne(newTicket);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Error creating ticket', error });
      }
    });

    // Vendor: Update ticket
    app.patch('/tickets/:id', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const id = req.params.id;
        const ticket = await ticketsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!ticket)
          return res.status(404).send({ message: 'Ticket not found.' });

        // Vendor can only update their own tickets
        if (
          req.decoded.role === 'vendor' &&
          ticket.vendorEmail !== req.decoded.email
        )
          return res.status(403).send({ message: 'Forbidden.' });

        // Cannot update rejected tickets
        if (ticket.status === 'rejected')
          return res
            .status(400)
            .send({ message: 'Cannot update rejected ticket.' });

        const { status, advertised, isHidden, ...updateData } = req.body; // strip admin-only fields
        const result = await ticketsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { ...updateData, updatedAt: new Date() } },
        );
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error updating ticket', error });
      }
    });

    // Vendor: Delete ticket
    app.delete('/tickets/:id', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const id = req.params.id;
        const ticket = await ticketsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!ticket)
          return res.status(404).send({ message: 'Ticket not found.' });

        if (
          req.decoded.role === 'vendor' &&
          ticket.vendorEmail !== req.decoded.email
        )
          return res.status(403).send({ message: 'Forbidden.' });

        const result = await ticketsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error deleting ticket', error });
      }
    });

    // ── Admin: Approve / Reject ticket ─────────
    // ✅ Fixed URL: /tickets/:id/status  (was /tickets/status/:id)
    app.patch(
      '/tickets/:id/status',
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { status } = req.body; // 'approved' | 'rejected'

          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status } },
          );
          res.send({ success: true, result });
        } catch (error) {
          res
            .status(500)
            .send({ message: 'Error updating ticket status', error });
        }
      },
    );

    // ── Admin: Toggle advertise ─────────────────
    // ✅ Fixed URL: /tickets/:id/advertise  (was /tickets/advertise/:id)
    // ✅ Fixed field: advertised  (was advertiseState / isAdvertised)
    app.patch(
      '/tickets/:id/advertise',
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { advertised } = req.body;

          if (advertised === true) {
            const count = await ticketsCollection.countDocuments({
              advertised: true,
            });
            if (count >= 6)
              return res
                .status(400)
                .send({ message: 'Max 6 tickets can be advertised.' });
          }

          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { advertised } },
          );
          res.send({ success: true, result });
        } catch (error) {
          res.status(500).send({ message: 'Error toggling advertise', error });
        }
      },
    );

    // ══════════════════════════════════════════
    // USER MANAGEMENT (Admin only)
    // ══════════════════════════════════════════

    // Get all users
    app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const result = await usersCollection
          .find({}, { projection: { password: 0 } })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching users', error });
      }
    });

    // Update user role
    app.patch('/users/role/:id', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { role } = req.body;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role } },
        );
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error updating role', error });
      }
    });

    // Mark vendor as fraud (hides their tickets too)
    app.patch('/users/fraud/:id', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const vendor = await usersCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        if (!vendor)
          return res.status(404).send({ message: 'User not found.' });

        await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { isFraud: true } },
        );

        // Hide all this vendor's tickets
        await ticketsCollection.updateMany(
          { vendorEmail: vendor.email },
          { $set: { isHidden: true } },
        );

        res.send({
          success: true,
          message: 'Vendor flagged and tickets hidden.',
        });
      } catch (error) {
        res.status(500).send({ message: 'Error flagging fraud', error });
      }
    });

    // ══════════════════════════════════════════
    // BOOKING ENDPOINTS
    // ⚠️ /bookings/vendor must come before /bookings/:id
    // ══════════════════════════════════════════

    // User: Create booking
    app.post('/bookings', verifyJWT, async (req, res) => {
      try {
        const booking = {
          ...req.body,
          createdAt: new Date(),
        };
        const result = await bookingsCollection.insertOne(booking);
        res.status(201).send({ success: true, insertId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Booking failed', error });
      }
    });

    // Vendor: See booking requests for their tickets
    app.get('/bookings/vendor', verifyJWT, verifyVendor, async (req, res) => {
      try {
        const email = req.query.email;

        if (req.decoded.role === 'vendor' && email !== req.decoded.email)
          return res.status(403).send({ message: 'Forbidden.' });

        // Get all tickets belonging to this vendor
        const vendorTickets = await ticketsCollection
          .find(
            { vendorEmail: email },
            { projection: { _id: 1, company: 1, title: 1 } },
          )
          .toArray();

        if (vendorTickets.length === 0) return res.send([]);

        const ticketIds = vendorTickets.map(t => t._id.toString());

        // Find bookings that match these ticket IDs
        const bookings = await bookingsCollection
          .find({ ticketId: { $in: ticketIds } })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(bookings);
      } catch (error) {
        res
          .status(500)
          .send({ message: 'Error fetching vendor bookings', error });
      }
    });

    // User: Get their own bookings | Admin: all bookings
    app.get('/bookings', verifyJWT, async (req, res) => {
      try {
        const { email } = req.query;
        const { role, email: decodedEmail } = req.decoded;

        let query = {};
        if (role === 'admin') {
          if (email) query.userEmail = email;
        } else {
          // Non-admin can only see their own
          query.userEmail = decodedEmail;
        }

        const result = await bookingsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching bookings', error });
      }
    });

    // Vendor: Accept or reject a booking
    app.patch(
      '/bookings/:id/status',
      verifyJWT,
      verifyVendor,
      async (req, res) => {
        try {
          const { status } = req.body; // 'accepted' | 'rejected'
          const result = await bookingsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status, updatedAt: new Date() } },
          );
          res.send({ success: true, result });
        } catch (error) {
          res
            .status(500)
            .send({ message: 'Error updating booking status', error });
        }
      },
    );

    // User: Mark booking as paid (called after Stripe payment)
    app.patch('/bookings/:id/pay', verifyJWT, async (req, res) => {
      try {
        const bookingId = req.params.id;
        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(bookingId),
        });

        if (!booking)
          return res.status(404).send({ message: 'Booking not found.' });

        // Security: only the booking owner can pay
        if (booking.userEmail !== req.decoded.email)
          return res.status(403).send({ message: 'Forbidden.' });

        // Update booking to paid
        await bookingsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          { $set: { status: 'paid', paidAt: new Date() } },
        );

        // Deduct seats from ticket
        if (booking.ticketId) {
          const ticketQuery = ObjectId.isValid(booking.ticketId)
            ? { _id: new ObjectId(booking.ticketId) }
            : { id: booking.ticketId };

          await ticketsCollection.updateOne(ticketQuery, {
            $inc: { seats: -Math.abs(Number(booking.quantity || 1)) },
          });
        }

        // Save transaction record
        await transactionsCollection.insertOne({
          bookingId: bookingId,
          amount: booking.price,
          ticketTitle: booking.company || booking.title || 'Ticket',
          userEmail: booking.userEmail,
          createdAt: new Date(),
        });

        res.send({ success: true, message: 'Payment confirmed.' });
      } catch (error) {
        res.status(500).send({ message: 'Payment processing failed', error });
      }
    });

    // User: Cancel booking (only if still pending)
    app.delete('/bookings/:id', verifyJWT, async (req, res) => {
      try {
        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!booking)
          return res.status(404).send({ message: 'Booking not found.' });

        // Only owner can cancel, and only if pending
        if (
          booking.userEmail !== req.decoded.email &&
          req.decoded.role !== 'admin'
        )
          return res.status(403).send({ message: 'Forbidden.' });

        if (booking.status !== 'pending' && req.decoded.role !== 'admin')
          return res
            .status(400)
            .send({ message: 'Can only cancel pending bookings.' });

        const result = await bookingsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Error cancelling booking', error });
      }
    });

    // ══════════════════════════════════════════
    // STRIPE PAYMENT ENDPOINTS
    // ══════════════════════════════════════════

    app.post('/create-payment-intent', verifyJWT, async (req, res) => {
      try {
        const { price } = req.body;
        if (!price || isNaN(price))
          return res.status(400).send({ message: 'Invalid price.' });

        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(Number(price) * 100),
          currency: 'bdt',
          payment_method_types: ['card'],
        });

        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({ message: 'Stripe error', error: error.message });
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
          quantity,
        } = req.body;

        await transactionsCollection.insertOne({
          transactionId,
          amount: finalPrice,
          ticketTitle: ticketTitle || 'Ticket',
          userEmail,
          createdAt: new Date(),
        });

        await bookingsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          { $set: { status: 'paid' } },
        );

        const ticketQuery = ObjectId.isValid(ticketId)
          ? { _id: new ObjectId(ticketId) }
          : { id: Number(ticketId) };

        await ticketsCollection.updateOne(ticketQuery, {
          $inc: { seats: -Math.abs(Number(quantity || 1)) },
        });

        res.send({ success: true, message: 'Payment confirmed.' });
      } catch (error) {
        res.status(500).send({ message: 'Payment confirmation failed', error });
      }
    });

    // User: Transaction history
    app.get('/transactions', verifyJWT, async (req, res) => {
      try {
        const { email } = req.query;

        // Security: user can only see own transactions
        const queryEmail =
          req.decoded.role === 'admin' ? email : req.decoded.email;
        const query = queryEmail ? { userEmail: queryEmail } : {};

        const result = await transactionsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching transactions', error });
      }
    });
  } finally {
    // Keep connection alive
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('🚀 TicketBari Server running!');
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
