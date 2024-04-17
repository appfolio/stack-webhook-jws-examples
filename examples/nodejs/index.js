const express = require('express');
const bodyParser = require('body-parser');
const jose = require('jose');

const app = express();
const port = process.env.PORT || 8000;

const JWKS = jose.createRemoteJWKSet(new URL('https://api.appfolio.com/.well-known/jwks.json'));

app.use(bodyParser.raw({
  type: 'application/json',
}));

async function verifySignature(req) {
  try {
    // @important! NodeJS converts the header names to lowercase, so we need to use the lowercase version
    const [encodedHeader, encodedSignature] = req.headers['x-jws-signature'].split('..');

    const encodedPayload = req.body.toString('base64url').replaceAll('=', '');

    const message = `${encodedHeader}.${encodedPayload}.${encodedSignature}`;

    await jose.compactVerify(message, JWKS);
    return true;
  } catch (error) {
    console.error('Failed to verify signature:', error);
    return false;
  }
}

app.post('/', async (req, res) => {
  if (await verifySignature(req)) {
    console.log('Webhook received and signature verified');
    res.sendStatus(200);
  } else {
    console.error('Invalid webhook signature');
    res.sendStatus(401);
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
