# AppFolio Webhooks
AppFolio provides support for webhooks through the API. Webhooks are HTTP-based callback functions that allow your app to receive real-time updates about events that occur in the AppFolio system. This repository contains example code for various languages demonstrating how to verify the signature of a webhook event notification sent by AppFolio.

For documentation, or a guide on how to use webhooks, please refer to your internal AppFolio documentation.

## Examples
- [Node.js](./examples/nodejs/index.js)
- [Go](./examples/go/main.go)
- [Ruby (Rails Controller)](./examples/ruby/rails_webhook_controller.rb)
- [Python](./examples/python/server.py)
<!-- TODO: Not implemented/broken -->
<!-- - [Java](./examples/java/main.java) -->

## Verify the Webhook Message Signature
AppFolio signs all outgoing webhooks to enable recipients to verify the authenticity and integrity of the received notifications. You must verify the webhook message signature in the event notification payload sent by AppFolio by executing the following steps. Any notifications that fail the webhook message signature verification must not be processed.
1. **Fetch Public Keys From AppFolio**
- Send a GET request to https://api.appfolio.com/.well-known/jwks.json. The endpoint will respond with a set of keys in JSON Web Key Set (JWKS) [format](https://datatracker.ietf.org/doc/html/rfc7517#section-5):
 
```json
{
  "keys": [
    {
      "alg": "PS256",
      "e": "AQAB",
      "kid": "...",
      "kty": "RSA",
      "n": "...",
      "use": "sig"
    }
  ]
}
```

2. **Read the Payload of the Webhook Request Sent by AppFolio**
- Take note of the value of the `X-JWS-Signature` header. The header is stored in the following format, however, the `BASE64URL(JWS Payload)` will be missing because AppFolio is using the detached payload:
- ``BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)``
```json
POST / HTTP/0.0
Host: example.com
Content-Type: application/json
X-JWS-Signature: xxxxxx..xxxxxx
{"client_id":"example_id","id":"example-event-uuid-value","topic":"work_order_updates","entity_id":"example-entity-uuid-value","update_timestamp":"2023-03-27T16:55:12Z","message_sent_at":"2023-08-28T23:18:27Z"}
```
3. **Extract the `BASE64URL(UTF8(JWS Protected Header))` from the signature**. This is the part before the `..`  in the `X-JWS-Signature` header value. 
4. **Extract the `BASE64URL(JWS Signature)` from the signature**. This is the part after the `..`  in the `X-JWS-Signature header` header value.
5. **Compute the `BASE64URL(JWS Payload)`**. Encode the body of the main request (the payload) using the unpadded alternate base64 encoding defined in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648). 
6. **Verify the Webhook Message Signature**
- Concatenate the encoded values from steps **3**, **4**, and **5** with `.` as a separator. For example: 
`BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)`
or:
`encoded-jose-header + "." + encoded-message-payload + "." + jws-signature`
- Verify the JWS signature of the computed message using the public keys fetched from **Step 1** of this section. We recommend utilizing a library that supports this verification in the coding language used for your application. Our sample code below gives examples of verifying the JWS signature of the computed message in several popular coding languages.  
- **Note**: AppFolio uses `RSASSA_PSS_SHA_256` as the signature algorithm. For additional information pertaining to this algorithm, click [here](https://datatracker.ietf.org/doc/html/rfc3447#section-8.1).

