var crypto = require('crypto-js');

module.exports = function(db) {
    return {
        // check for token and decrypt
        requireAuthentication: function(req, res, next) {
            // pull request header
            var token = req.get('Auth') || '';
            // find user hased token from the database
            db.token.findOne({
                where: {
                    tokenHash: crypto.MD5(token).toString()
                }
            }).then(function(tokenInstance) {
                // check if it is a hased token exist
                if(!tokenInstance) {
                    throw new Error();
                }
                // Succes
                req.token = tokenInstance;
                return db.user.findByToken(token);
            }).then(function(user) {
                req.user = user;
                next();
            }).catch(function() {
                res.status(401).send();
            });
        }
    };
};
