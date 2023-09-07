const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;

module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    updateLastLogout,
    authorizeRole
};

async function authenticate({ username, password, clientIP }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        user.lastLogin = new Date();
        user.clientIP = clientIP;
        console.log('user logged in successfully', user);
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        await user.save();
        return {
            ...userWithoutHash,
            token
        };
    }
}

async function authorizeRole(headers) {
    try {
        // Check if the user has the AUDITOR 
        const { role, id } = headers;
        const users = await User.find();
        if (!role.includes('Auditor')) {
            return { error: 'Unauthorized' };
        }
        return users
    } catch (error) {
        console.error(error);
        return { error: 'Internal Server Error' };
    }
}



async function updateLastLogout(authData) {
    const { username, password } = authData
    const user = await User.findOne({ username });
    user.lastLogout = new Date();
    await user.save();
}


async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}