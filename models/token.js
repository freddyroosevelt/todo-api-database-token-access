// Store Tokens in database that can be deleted
var crypto = require('crypto-js');

module.exports = function(sequelize, DataTypes) {
    return sequelize.define('token', {
        // token used for validation
        token: {
            type: DataTypes.VIRTUAL,
            allowNull: false,
            validate: {
                len: [1]
            },
            set: function(value) {
                // hash token
                var hash = crypto.MD5(value).toString();
                this.setDataValue('token', value);
                this.setDataValue('tokenHash', hash);
            }
        },
        tokenHash: DataTypes.STRING
    });
};
