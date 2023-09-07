const express = require('express');
const router = express.Router();
const userService = require('./user.service');
// const auditController = require('../controllers/auditController');
// const { authorizeRole } = require('../middleware/authMiddleware');

// routes
router.post('/authenticate', authenticate);
router.get('/audit', authorizeRole);
router.post('/register', register);
router.get('/', getAll);
router.get('/current', getCurrent);
router.get('/:id', getById);
router.put('/:id', update);
router.delete('/:id', _delete);
router.post('/logout', logout);

module.exports = router;

console.log('inside users')
function authenticate(req, res, next) {
    const { username, password } = req.body;
    const clientIP = req.ip; // Get the client's IP address from the request
    userService.authenticate({ username, password, clientIP })
        .then(user => user ? res.json(user) : res.status(400).json({ message: 'Username or password is incorrect' }))
        .catch(err => next(err));
}

function authorizeRole(req, res, next) {
    userService.authorizeRole(req.headers)
        .then(users => res.json(users))
        .catch(err => next(err));
}

function logout(req, res, next) {
    userService.updateLastLogout(req.body.authData)
    res.status(200).json({ message: 'Logged out successfully' });
}

function register(req, res, next) {
    const { firstName, lastName, username, password, role } = req.body;
    const user = { firstName, lastName, username, password, role };
    userService.create(user)
        .then(() => { res.json({}) })
        .catch(err => next(err));
}

function getAll(req, res, next) {
    userService.getAll()
        .then(users => res.json(users))
        .catch(err => next(err));
}

function getCurrent(req, res, next) {
    userService.getById(req.user.sub)
        .then(user => user ? res.json(user) : res.sendStatus(404))
        .catch(err => next(err));
}

function getById(req, res, next) {
    userService.getById(req.params.id)
        .then(user => user ? res.json(user) : res.sendStatus(404))
        .catch(err => next(err));
}

function update(req, res, next) {
    userService.update(req.params.id, req.body)
        .then(() => res.json({}))
        .catch(err => next(err));
}

function _delete(req, res, next) {
    userService.delete(req.params.id)
        .then(() => res.json({}))
        .catch(err => next(err));
}

async function getAuditLogs(req, res) {
    try {
        // Check if the user has the AUDITOR role
        const user = await User.findById(req.user.id);
        if (!user || !user.roles.includes('AUDITOR')) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        // If authorized, retrieve audit logs
        const auditLogs = await AuditLog.find().select('user timestamp clientIP');

        res.json(auditLogs);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
}