require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // <-- CRITICAL FIX: Added crypto import
const Razorpay = require('razorpay');
const jwt = require('jsonwebtoken');

// Import Mongoose Models
const User = require('./models/User');
const ValorantMatch = require('./models/ValorantMatch');
const Payment = require('./models/Payment'); // <-- CRITICAL FIX: Added Payment model import

const app = express();

// Accept raw body for webhook signature verification
app.post(
    '/razorpay-webhook',
    express.raw({ type: 'application/json' }),
    (req, res) => {
        const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
        const signature = req.headers['x-razorpay-signature'];
        const payload = req.body; // this is a Buffer

        // Create expected signature
        const expectedSignature = crypto
            .createHmac('sha256', webhookSecret)
            .update(payload)
            .digest('hex');

        if (signature !== expectedSignature) {
            return res.status(400).send('Invalid webhook signature');
        }

        // Parse the event
        const event = JSON.parse(payload.toString());

        // Handle payment events
        if (event.event === 'payment.captured') {
            // Example: Update payment/order in your DB as "paid"
            console.log("Payment captured: ", event.payload.payment.entity.id);
            // You can fetch `event.payload.payment.entity.order_id` to update matching order
        } else if (event.event === 'payment.failed') {
            // Example: Mark as failed in your DB
            console.log("Payment failed: ", event.payload.payment.entity.id);
        }
        // ... handle other events as needed

        // Respond quickly to Razorpay
        res.json({ status: 'ok' });
    }
);

app.use(express.json());

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to Database"))
    .catch(err => console.error("MongoDB connection error:", err));

// --- Razorpay Instance ---
// CRITICAL FIX: Initialized Razorpay only ONCE.
const razorpayInstance = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const otpStore = {}; // In production, use Redis or DB

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    const otp = otpGenerator.generate(4, { upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false, digits: true });
    otpStore[email] = otp;

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'vamshiediga2608@gmail.com',
            pass: 'qmxj nosz firm izmk', // Not your Gmail password!
        },
    });

    const mailOptions = {
        from: 'vamshiediga2608@gmail.com',
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP is ${otp}`,
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'OTP sent successfully' });
    } catch (err) {
        console.error('Failed to send OTP:', err);
        res.status(500).json({ success: false, message: 'OTP sending failed' });
    }
});

app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (otpStore[email] === otp) {
        res.json({ success: true, message: 'OTP verified!' });
    } else {
        res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
});

// JWT Admin Middleware
function adminOnly(req, res, next) {
    const authHeader = req.header('Authorization');
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });
    const token = authHeader.replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Admins only' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.json({ success: true, message: 'Account creation successful' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Account creation failed' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const validUsername = await User.findOne({ username });
        const validEmail = await User.findOne({ email: username });

        let user = validUsername || validEmail;
        if (user) {
            const validPw = await bcrypt.compare(password, user.password);
            if (validPw) {
                // Issue JWT with role
                const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '2h' });
                return res.json({ success: true, message: 'User exist', token, role: user.role });
            } else {
                // Only return success: false for invalid credentials
                return res.json({ success: false, message: 'Invalid credentials' });
            }
        } else {
            // Only return success: false for user not found
            res.status(400).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/valorant-matches', async (req, res) => {
    try {
        const { mapName, mode, players, maxPlayers, prizePool, fee } = req.body;
        const newValoMatch = new ValorantMatch({ mapName, mode, players, maxPlayers, prizePool, fee });
        await newValoMatch.save();
        res.status(200).json({ success: true, message: 'Match added' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Something went wrong' });
    }
});

app.get('/valorant-matches', async (req, res) => {
    try {
        const matches = await ValorantMatch.find({});
        res.status(200).json(matches)
    } catch (err) {
        res.status(500).json({ message: 'Failed to retrieve data' });
    }
});

// --- Razorpay Payment Endpoints ---

app.post('/create-order', async (req, res) => {
    try {
        const { _id, currency = 'INR', receipt, notes } = req.body;

        const match = await ValorantMatch.find({ _id: _id });
        if (!match) {
            return res.status(404).json({ success: false, message: 'Match not found' });
        }
        const amount = match.fee;

        if (!amount || amount <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid amount' });
        }

        const options = {
            amount: amount * 100, // Amount in paise
            currency,
            receipt,
            notes
        };

        const order = await razorpayInstance.orders.create(options);

        res.json({
            success: true,
            order_id: order.id,
            amount: order.amount,
            currency: order.currency,
            key_id: process.env.RAZORPAY_KEY_ID
        });
    } catch (error) {
        console.error('Error creating Razorpay order:', error);
        res.status(500).json({ success: false, message: 'Failed to create order' });
    }
});

app.post('/verify-payment', async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const razorpayOrder = await razorpayInstance.orders.fetch(razorpay_order_id);

        const body = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest('hex');

        if (expectedSignature === razorpay_signature) {
            await Payment.create({
                razorpay_order_id,
                razorpay_payment_id,
                razorpay_signature,
                amount: razorpayOrder.amount / 100,
                currency: razorpayOrder.currency,
                team_name: razorpayOrder.notes?.team_name,
                lobby: razorpayOrder.notes?.lobby,
                players: razorpayOrder.notes?.players, // stored as a JSON string
                status: 'success',
            });
            res.json({ success: true, message: 'Payment verified successfully' });
        } else {
            res.status(400).json({ success: false, message: 'Invalid payment signature' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).json({ success: false, message: 'Payment verification failed' });
    }
});


const PORT = process.env.PORT || 2000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

