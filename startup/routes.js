const express = require('express');
// const genres = require('../routes/genres');
// const customers = require('../routes/customers');
// const movies = require('../routes/movies');
// const rentals = require('../routes/rentals');
const users = require('../routes/users');
const auth = require('../routes/auth');
const resetpass = require('../routes/resetpass');
// const returns = require('../routes/returns');
const error = require('../middleware/error');


var swaggerUi = require('swagger-ui-express'),
// let str = process.env=== 'prod'? '../swagger-prod.json':'../swagger.json';
// let swaggerDocument = require(str);

    swaggerDocument = require('../swagger.json');

module.exports = function(app) {
  app.use(express.json());
  // app.use('/api/genres', genres);
  // app.use('/api/customers', customers);
  //  app.use('/api/movies', movies);
  // app.use('/api/rentals', rentals);
  app.use('/api/users', users);
  app.use('/api/auth', auth);
  app.use('/api/resetpass', resetpass)
  // app.use('/api/returns', returns);

  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
  app.use('/api/', express.Router());

  app.use(error);
}