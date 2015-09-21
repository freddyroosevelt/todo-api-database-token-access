var bcrypt = require('bcrypt');
var underScore = require('underscore');
var crypto = require('crypto-js');
var jwt = require('jsonwebtoken');

module.exports = function(sequelize, DataTypes) {
    var user = sequelize.define('user', {
        // email and password required
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isEmail: true
            }
        },
        salt: {
            type: DataTypes.STRING
        },
        password_hash: {
            type: DataTypes.STRING
        },
        password: {
            type: DataTypes.VIRTUAL,
            allowNull: false,
            validate: {
                len: [7, 100]
            },
            set: function(value) {
                // generate salt
                var salt = bcrypt.genSaltSync(10);
                // hash password
                var hashedPassword = bcrypt.hashSync(value, salt);

                this.setDataValue('password', value);
                this.setDataValue('salt', salt);
                this.setDataValue('password_hash', hashedPassword);
            }
        }

    }, {
        hooks: {
            beforeValidate: function(user, options) {
                // user.email to lowercase if its a string and exists
                if(typeof user.email === 'string') {
                    user.email = user.email.toLowerCase();
                }
            }
        },
        classMethods: {
            authenticate: function(body) {
                return new Promise(function(resolve, reject) {

                    // Error (400) bad request, if no user email/password input
                    if(typeof body.email !== 'string' || typeof body.password !== 'string') {
                        console.log('----- -----');
                        console.log('Error: User email and password can not be empty!');
                        console.log('----- -----');
                        return reject(); //res.status(400).send();
                    }

                    // find user by email
                    user.findOne({
                        where: {
                            email: body.email
                        }
                    }).then(function(user) {
                        // If no user or if user email with the password they signed up with
                        // dont match. also check if pw is equal to user
                        if(!user || !bcrypt.compareSync(body.password, user.get('password_hash'))) {
                            // No user exist
                            console.log('----- -----');
                            console.log('No user found with that email or password do not match!');
                            console.log('----- -----');
                            return reject(); //res.status(401).send();
                        }

                        // return the user with email found & only the fields we want to expose
                        resolve(user);

                    }, function(e) {
                        //Error
                        console.log('----- -----');
                        console.log('No user found in the database with that email!');
                        console.log('----- -----');
                        //res.status(500).send();
                        reject();
                    });
                });
            },
            findByToken: function(token) {
                return new Promise(function(resolve, reject) {
                    // Get back original token data
                    try {
                        var decodedJWT = jwt.verify(token, 'qwerty098');
                        // decrypt data
                        var bytes = crypto.AES.decrypt(decodedJWT.token, 'abc123!@#!');
                        // convert to json
                        var tokenData = JSON.parse(bytes.toString(crypto.enc.Utf8));

                        // find user with token id
                        user.findById(tokenData.id).then(function(user) {
                            if(user) {
                                resolve(user);
                            }else {
                                reject();
                            }
                        }, function(e) {
                            reject();
                        });
                    }catch(e) {
                        // Error
                        reject();
                    }
                });
            }
        },
        instanceMethods: {
            toPublicJSON: function() {
                var json = this.toJSON();
                return underScore.pick(json, 'id', 'email', 'createdAt', 'updatedAt');
            },
            generateToken: function(type) {
                // encrypted user data token
                if(!underScore.isString(type)) {
                    return undefined;
                }

                // try/catch block
                try {

                    // create json string format
                    var stringData = JSON.stringify({id: this.get('id'), type: type});
                    // encrypt the json data string
                    var encryptedData = crypto.AES.encrypt(stringData, 'abc123!@#!').toString();
                    // create new encrypted web token
                    var token = jwt.sign({
                        token: encryptedData
                    }, 'qwerty098');

                    return token;

                }catch(e) {
                    // Error
                    console.log('----- -----');
                    console.log('No valid token generated!');
                    console.log(e);
                    console.log('----- -----');
                    return undefined;
                }
            }
        }
    });

    return user;
};
