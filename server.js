require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const Item = require('./models/Item');
const User = require('./models/User');
const app = express();
const flash = require('express-flash');

const CURRENCY = process.env.CURRENCY || 'GBP';
const LIST_NAME = process.env.LIST_NAME || 'My Wishlist';
const LIST_TYPE = process.env.LIST_TYPE || 'bday';
const DBHOST = process.env.DBHOST || 'localhost:27017';
const DBNAME = process.env.DBNAME || 'simple-wishlist';
const PORT = process.env.PORT || 8092;

// Currency symbols mapping
const currencySymbols = {
    'USD': '$',
    'GBP': '£',
    'EUR': '€',
};

// List Types
const occasion = {
    'bday': 'wishlist-present.png',
    'xmas': 'wishlist-xmas.png',
    'wedding': 'wishlist-wedding.png',
};

const connectWithRetry = (retries) => {
    return mongoose.connect(`mongodb://${DBHOST}/${DBNAME}`, {
        serverSelectionTimeoutMS: 3000,
    })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        if (retries > 0) {
            console.log(`MongoDB connection failed: (mongodb://${DBHOST}/${DBNAME}).`);
            console.log(`Retrying... (${retries} attempts left)`);
            setTimeout(() => connectWithRetry(retries - 1), 1000);
        } else {
            console.error(`Failed to connect to (mongodb://${DBHOST}/${DBNAME}) after multiple attempts.`);
            console.error(err);
            console.error('App Shutting Down...');
            process.exit(1);
        }
    });
};

connectWithRetry(3);

app.use(session({
    secret: process.env.SESSION_SECRET || 'yjtfkuhgkuygibjlljbvkuvykjvjlkvv',
    resave: false,
    saveUninitialized: false
}));

app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        console.log('Login attempt for username:', username);
        const user = await User.findOne({ username: username });
        if (!user) {
            console.log('User not found:', username);
            return done(null, false, { message: 'Incorrect username.' });
        }
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user);
    } catch (err) {
        console.error('Error during login:', err);
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

const auth = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
};

const checkAdminSetup = async (req, res, next) => {
    const adminCount = await User.countDocuments();
    if (adminCount === 0) {
        return res.redirect('/setup');
    }
    next();
};

app.use((req, res, next) => {
    if (req.path !== '/setup') {
        return checkAdminSetup(req, res, next);
    }
    next();
});

app.get('/setup', async (req, res) => {
    const adminCount = await User.countDocuments();
    if (adminCount === 0) {
        res.render('setup', {
            listType: occasion[LIST_TYPE]
        });
    } else {
        res.redirect('/');
    }
});

app.post('/setup', [
    body('username').trim().isLength({ min: 3 }).escape(),
    body('password').trim().isLength({ min: 4 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('Validation errors:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        const adminCount = await User.countDocuments();
        if (adminCount === 0) {
            const { username, password } = req.body;
            console.log('Setting up admin user:', username);
            const hashedPassword = await bcrypt.hash(password, 10);
            const user = new User({ username, password: hashedPassword });
            await user.save();
            console.log('Admin user created successfully');

            req.flash('success', 'Admin user created successfully. Please log in.');
            return res.redirect(302, '/login');
        } else {
            console.log('Admin user already exists');
            req.flash('info', 'Admin user already exists.');
            return res.redirect(302, '/login');
        }
    } catch (error) {
        console.error('Error in setup route:', error);
        req.flash('error', 'An error occurred during setup. Please try again.');
        return res.redirect(302, '/setup');
    }
});

app.get('/login', (req, res) => {
    res.render('login', {
        listType: occasion[LIST_TYPE],
        messages: {
            error: req.flash('error'),
            success: req.flash('success'),
            info: req.flash('info')
        }
    });
});

app.post('/login', [
    body('username').trim().escape(),
    body('password').trim()
], (req, res, next) => {  
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error('Error during authentication:', err);
            return next(err);
        }
        if (!user) {
            console.log('Authentication failed:', info.message);
            req.flash('error', info.message);
            return res.redirect('/');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Error during login:', err);
                return next(err);
            }
            console.log('User logged in successfully:', user.username);
            return res.redirect('/admin');
        });
    })(req, res, next);
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// Route to create new user (MUST be before /:username/ route)
app.get('/register', (req, res) => {
    res.render('register', {
        listType: occasion[LIST_TYPE],
        messages: {
            error: req.flash('error'),
            success: req.flash('success')
        }
    });
});

app.post('/register', [
    body('username').trim().isLength({ min: 3 }).escape(),
    body('password').trim().isLength({ min: 4 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('Validation errors:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ username: username });
        if (existingUser) {
            req.flash('error', 'Username already exists. Please choose another.');
            return res.redirect('/register');
        }

        console.log('Creating new user:', username);
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        console.log('User created successfully:', username);

        req.flash('success', 'User created successfully. You can now log in.');
        return res.redirect('/');
    } catch (error) {
        console.error('Error in register route:', error);
        req.flash('error', 'An error occurred during registration. Please try again.');
        return res.redirect('/register');
    }
});

// New route: Show all users
app.get('/', async (req, res) => {
    try {
        const users = await User.find();
        res.render('user-select', { 
            users,
            listType: occasion[LIST_TYPE]
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error loading users');
    }
});

// New route: User-specific wishlist
app.get('/:username/', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) {
            return res.status(404).send('User not found');
        }
        const wishlistItems = await Item.find({ purchased: false, userId: user._id }).sort({ priority: -1 });
        const purchasedItems = await Item.find({ purchased: true, userId: user._id }).sort({ _id: -1 });
        res.render('index', { 
            wishlistItems, 
            purchasedItems, 
            currency: CURRENCY, 
            currencySymbol: currencySymbols[CURRENCY],
            listName: `${req.params.username}'s ${LIST_NAME}`,
            listType: occasion[LIST_TYPE],
            username: req.params.username
        });
    } catch (error) {
        console.error('Error fetching wishlist:', error);
        res.status(500).send('Error loading wishlist');
    }
});

// New route: User-specific login
app.get('/:username/login', (req, res) => {
    res.render('login', {
        listType: occasion[LIST_TYPE],
        username: req.params.username,
        messages: {
            error: req.flash('error'),
            success: req.flash('success'),
            info: req.flash('info')
        }
    });
});

app.post('/:username/login', [
    body('password').trim()
], async (req, res, next) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) {
            req.flash('error', 'User not found.');
            return res.redirect(`/${req.params.username}/login`);
        }
        const isValid = await bcrypt.compare(req.body.password, user.password);
        if (!isValid) {
            req.flash('error', 'Incorrect password.');
            return res.redirect(`/${req.params.username}/login`);
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Error during login:', err);
                return next(err);
            }
            console.log('User logged in successfully:', user.username);
            return res.redirect(`/${user.username}/admin`);
        });
    } catch (error) {
        console.error('Error during login:', error);
        req.flash('error', 'An error occurred during login.');
        res.redirect(`/${req.params.username}/login`);
    }
});

app.get('/:username/admin', auth, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) {
            return res.status(404).send('User not found');
        }
        const items = await Item.find({ userId: user._id }).sort({ priority: -1 });
        res.render('admin', {
            listType: occasion[LIST_TYPE],
            currency: CURRENCY, 
            currencySymbol: currencySymbols[CURRENCY],
            items: items,
            username: req.params.username
        });
    } catch (error) {
        console.error('Error fetching admin items:', error);
        res.status(500).send('Error loading admin page');
    }
});

app.post('/:username/admin/add-item', auth, [
    body('name').trim().escape(),
    body('price').isFloat({ min: 0, max: 1000000 }).toFloat(),
    body('url').isURL().customSanitizer(value => {
        if (!/^https?:\/\//i.test(value)) {
            value = 'http://' + value;
        }
        return value;
    }),
    body('imageUrl').isURL().customSanitizer(value => {
        if (!/^https?:\/\//i.test(value)) {
            value = 'http://' + value;
        }
        return value;
    }),
    body('priority').isInt({ min: 0, max: 10 }).toInt()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, price, url, imageUrl, priority } = req.body;
    
    const sanitizedName = sanitizeHtml(name, {
        allowedTags: [],
        allowedAttributes: {}
    });

    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) {
            return res.status(404).send('User not found');
        }
        await Item.create({ name: sanitizedName, price, url, imageUrl, purchased: false, priority, userId: user._id });
        res.redirect(`/${req.params.username}/admin`);
    } catch (error) {
        console.error('Error adding item:', error);
        res.status(500).send('Error adding item');
    }
});

app.get('/:username/admin/edit-item/:id', auth, async (req, res) => {
    try {
        const item = await Item.findById(req.params.id);
        if (!item) {
            return res.status(404).send('Item not found');
        }
        res.render('edit-item', {
            listType: occasion[LIST_TYPE],
            currency: CURRENCY,
            currencySymbol: currencySymbols[CURRENCY],
            item: item,
            username: req.params.username
        });
    } catch (error) {
        console.error('Error fetching item:', error);
        res.status(500).send('Error fetching item');
    }
});

app.post('/:username/admin/update-item/:id', auth, [
    body('name').trim().escape(),
    body('price').isFloat({ min: 0, max: 1000000 }).toFloat(),
    body('url').isURL().customSanitizer(value => {
        if (!/^https?:\/\//i.test(value)) {
            value = 'http://' + value;
        }
        return value;
    }),
    body('imageUrl').isURL().customSanitizer(value => {
        if (!/^https?:\/\//i.test(value)) {
            value = 'http://' + value;
        }
        return value;
    }),
    body('priority').isInt({ min: 0, max: 10 }).toInt()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, price, url, imageUrl, priority } = req.body;
    
    const sanitizedName = sanitizeHtml(name, {
        allowedTags: [],
        allowedAttributes: {}
    });

    try {
        await Item.findByIdAndUpdate(req.params.id, {
            name: sanitizedName,
            price,
            url,
            imageUrl,
            priority
        });
        res.redirect(`/${req.params.username}/admin`);
    } catch (error) {
        console.error('Error updating item:', error);
        res.status(500).send('Error updating item');
    }
});

app.post('/:username/admin/delete-item/:id', auth, async (req, res) => {
    try {
        await Item.findByIdAndDelete(req.params.id);
        res.redirect(`/${req.params.username}/admin`);
    } catch (error) {
        console.error('Error deleting item:', error);
        res.status(500).send('Error deleting item');
    }
});

app.post('/:username/purchase/:id', async (req, res) => {
    try {
        await Item.findByIdAndUpdate(req.params.id, { purchased: true });
        res.redirect(`/${req.params.username}/`);
    } catch (error) {
        console.error('Error purchasing item:', error);
        res.status(500).send('Error purchasing item');
    }
});

app.post('/:username/restore/:id', async (req, res) => {
    try {
        await Item.findByIdAndUpdate(req.params.id, { purchased: false });
        res.redirect(`/${req.params.username}/`);
    } catch (error) {
        console.error('Error restoring item:', error);
        res.status(500).send('Error restoring item');
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});