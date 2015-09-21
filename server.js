/*
#Todo API

##Todo API w/ a backend database using user token for validation to create/fetch items.

### Objective of API:

####1. POST/GET/DELETE/UPDATE a new Todo item.
####2. User login/logout with email and password (must be unique & password must be 7 chars in len)
####3. Delete/Filter/Search a Todo item.
####4. Web token access only to each unique user.
####5. Todos are private with user association id access.

##### Getting Started:
  1. First run: npm install for all node modules needed.
  2. Start app: node server.js
  3. Use Postman to test and/or use SQlite Browser to see your database.
  4. Make sure you copy/paste auth token created to use for testing in postman.
  5. You can use create user then login user to start testing.


*/

var express = require('express');
var bodyParser = require('body-parser');
var underScore = require('underscore');
var db = require('./db.js');
var bcrypt = require('bcrypt');
var middleware = require('./middleware.js')(db);

var app = express();
var PORT = process.env.PORT || 3000;
var todos = [];
var todoNextId = 1;


app.use(bodyParser.json());

// GET /todos and/or GET/todos?completed=true and/or by GET/todos?q=work
app.get('/todos', middleware.requireAuthentication, function(req, res) {
    // Filter for a completed Todo item with user ID association
    var query = req.query;
    var where = {
        userId: req.user.get('id')
    };

    if(query.hasOwnProperty('completed') && query.completed === 'true') {
        where.completed = true;
    }else if(query.hasOwnProperty('completed') && query.completed === 'false') {
        where.completed = false;
    }

    if(query.hasOwnProperty('q') && query.q.length > 0) {
        where.description = {
            $like: '%' + query.q + '%'
        };
    }

    db.todo.findAll({where: where}).then(function(todos) {
        res.json(todos);
    }, function(e) {
        res.status(500).send();
    });

});

// GET /todos/:id
app.get('/todos/:id', middleware.requireAuthentication, function(req, res) {
    var todoId = parseInt(req.params.id, 10);

    db.todo.findOne({
        where: {
            id: todoId,
            userId: req.user.get('id')
        }
    }).then(function(todo) {
        if(!!todo) {
            res.json(todo.toJSON());
        }else {
            res.status(404).send();
        }
    }, function(e) {
        res.status(500).send();
    });
});


// add todos through the Api
// POST REQUEST /todos - api route
app.post('/todos', middleware.requireAuthentication, function(req, res) {
    var body = underScore.pick(req.body, 'description', 'completed');

    // Call create on db.todo
    db.todo.create(body).then(function(todo) {

        // create user association with user id
        req.user.addTodo(todo).then(function() {
            return todo.reload();
        }).then(function(todo) {
            res.json(todo.toJSON());
        });
    }, function(e) {
        res.status(400).json(e);
    });
});

// DELETE /todos/:id
// Delete a todo by its id
app.delete('/todos/:id', middleware.requireAuthentication, function(req,res) {
    var todoId = parseInt(req.params.id, 10);

    db.todo.destroy({
        // Find the todo item
        where: {
            id: todoId,
            userId: req.user.get('id')
        }
    }).then(function(rowsDeleted) {
        if(rowsDeleted === 0) {
            res.status(404).json({
                // Error:
                error: 'No Todo item with that ID found!'
            });
        }else {
            // Success: found a todo item to delete
            res.status(204).send();
        }

    }, function() {
        res.status(500).send();
    });
});

// PUT /todos/:id
// Update/Create a Todo item
app.put('/todos/:id', middleware.requireAuthentication, function(req, res) {
    var todoId = parseInt(req.params.id, 10);
    var body = underScore.pick(req.body, 'description', 'completed');
    // store the values of the todos in the todos array
    var attributes = {};


    // check if 'completed' attribute exist and if so validate it
    if(body.hasOwnProperty('completed')) {
        attributes.completed = body.completed;
    }

    // check if 'description' attribute exist and if so validate it
    if(body.hasOwnProperty('description')) {
        attributes.description = body.description;
    }

    db.todo.findOne({
        where: {
            id: todoId,
            userId: req.user.get('id')
        }
    }).then(function(todo) {
        // If findById goes well
        if(todo) {
            // Find id with success
            todo.update(attributes).then(function(todo) {
                // Success for the todo Update
                res.json(todo.toJSON());
                console.log('----- -----');
                console.log('Succes: Your Todo item has been updated!');
                console.log('----- -----');
            }, function(e) {
                //If todo update fails
                res.status(400).json(e);
            });

        }else {
            res.status(404).send();
            console.log('----- -----');
            console.log('Todo item to be updated, not found!');
            console.log('----- -----');
        }
    }, function() {
        // If findById fails/ goes wrong
        res.status(500).send();
    });

});


app.post('/users', function(req, res) {
    var body = underScore.pick(req.body, 'email', 'password');

    db.user.create(body).then(function(user) {
        // Success: email must be unique & password must be 7 chars in len
        res.json(user.toPublicJSON());
    }, function(e) {
        // Error
        res.status(400).json(e);
        console.log('----- -----');
        console.log('Error: something went wrong with email and password for user!');
        console.log('----- -----');
    });
});

// user login with email and password
// POST /users/login
app.post('/users/login', function(req, res) {
    var body = underScore.pick(req.body, 'email', 'password');
    var userInstance;

    db.user.authenticate(body).then(function(user) {
        // success
        var token = user.generateToken('authentication');
        userInstance = user;
        // save hased token in the database
        return db.token.create({
            token: token
        });

    }).then(function(tokenInstance) {
        res.header('Auth', tokenInstance.get('token')).json(userInstance.toPublicJSON());
    }).catch(function() {
        // Error
        res.status(401).send();
        console.log('----- -----');
        console.log('User Not Found!');
        console.log('----- -----');
    });
});

// DELETE /users/login - logout
app.delete('/users/login', middleware.requireAuthentication, function(req, res) {
    // trash the hased token and logout user
    req.token.destroy().then(function() {
        res.status(204).send();
        console.log('User logged out');
    }).catch(function() {
        res.status(500).send();
        console.log('Error logging out');
    });
});

// Sync the db and run server
// force: true is to clear the database each time its ran.
db.sequelize.sync({force: true}).then(function() {
    // DB & Server listening on port 3000
    app.listen(PORT, function() {
        console.log('----- -----');
        console.log('Server Running on http://localhost' + ':' + PORT);
        console.log('----- -----');
    });
});
