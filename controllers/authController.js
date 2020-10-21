const passport = require('passport');
const crypto = require('crypto');
const mongoose = require('mongoose');
const promisify = require('es6-promisify');
const User = mongoose.model('User');
const mail = require('../handlers/mail');


exports.login = passport.authenticate('local', {
    failureRedirect: '/login',
    failureFlash: 'Failed Login!',
    successRedirect: '/',
    successFlash: 'You now logged in!'
});

exports.logout = (req, res) => {
    req.logout();
    req.flash('success', 'You now logged out!');
    res.redirect('/');
};

exports.isLoggedIn = (req, res, next) => {
    // first check if user is authenticated
    if(req.isAuthenticated()) {
        next(); // you are logged in!
        return;
    }
    req.flash('error', 'Oops you must be logged in to do that!');
    res.redirect('/login');
};

exports.forgot = async (req, res) => {
    // 1. See if a user with that email exits
    const user = await User.findOne({ email: req.body.email });
    if(!user) {
        req.flash('error', 'No account with that email exists.'); // if you using public website substitute the message with Reset been send to your email for a private practices.
        return res.redirect('/login');
    }
    // 2. Set reset tokens and expiry on their account 
    user.resetPasswordToken = crypto.randomBytes(20).toString('hex'); // creating random string with a random token
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour permission to reset the password
    await user.save(); 
    // 3. Send them an email with the token
    const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
    await mail.send({
        user, 
        subject: 'Password Reset',
        resetURL,
        filename: 'password-reset'
    })
    req.flash('success', `You have been emailed a password reset link.`);
    // 4. Redirect them to login page
    res.redirect('/login');
}

exports.reset = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) {
        req.flash('error', 'Password reset is invalid or has expired');
        return res.redirect('/login');
    };
    // if there is a user, show the rest password form 
    res.render('reset', { title: 'Reset your Password' });
};

exports.confirmedPasswords = (req, res, next) => {
    // use square brackets if you have a dash in the name
    if (req.body.password === req.body['password-confirm']){
        next(); // keep it going
        return;
    };
    req.flash('error', 'Passwords do not match!');
    res.redirect('back');
};

exports.update = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) {
        req.flash('error', 'Password reset is invalid or has expired');
        return res.redirect('/login');
    };
    const setPassword = promisify(user.setPassword, user);
    await setPassword(req.body.password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    // remove token and expiration date from mango db.
    const updatedUser = await user.save();
    await req.login(updatedUser);
    req.flash('success', 'Nice! Your password has been reset! You are now logged in!');
    res.redirect('/');
}