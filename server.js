const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const jwt = require('express-jwt');
const jwtAuthz = require('express-jwt-authz');
const jwksRsa = require('jwks-rsa');
const cors = require('cors');
const { join } = require('path');
const authConfig = require('./auth_config.json');

const app = express();

if (!authConfig.domain || !authConfig.audience) {
  throw 'Please make sure that auth_config.json is in place and populated';
}

const corsOptions =  {
  origin: 'http://localhost:3000'
};

app.use(cors(corsOptions));
app.use(morgan('dev'));
app.use(helmet());

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithm: ['RS256']
});

const checkScopes = jwtAuthz(['read:flights'], { customScopeKey: "permissions" });

app.get('/api/public', (req, res) => {
  res.send({
    msg: 'Hello from a public endpoint! You don\'t need to be authenticated to see this.'
  });
});

app.get('/api/private', checkJwt, (req, res) => {
  res.send({
    msg: 'Hello from a private endpoint! You need to be authenticated to see this.'
  });
});

app.get('/api/external', checkJwt, (req, res) => {
  res.send({
    msg: 'Your access token was successfully validated!'
  });
});

app.get('/api/permission', checkJwt, checkScopes, (req, res) => {
  res.send({
    msg: 'Your access token AND PERMISSION was successfully validated!'
  });
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(join(__dirname, 'dist', 'login-demo')));

  app.get('/*', (_, res) => {
    res.sendFile(join(__dirname, 'dist', 'login-demo', 'index.html'));
  });
}

const port = process.env.NODE_ENV === 'production' ? 3010 : 3001;

app.listen(port, () => console.log(`Server started on port ${port}`));
