package com.appfolio.stackwebhookjws.stackwebhookjws;

import java.security.Key;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class StackWebhookJwsApplication {

  Logger logger = LoggerFactory.getLogger(StackWebhookJwsApplication.class);

  public static void main(String[] args) {
    SpringApplication.run(StackWebhookJwsApplication.class, args);
  }

  @PostMapping("/")
  public ResponseEntity<String>
  webhook(@RequestHeader("X-JWS-Signature") String signature,
          @RequestBody byte[] body) {
    HttpsJwks httpsJkws =
        new HttpsJwks("https://api.appfolio.com/.well-known/jwks.json");
    HttpsJwksVerificationKeyResolver httpsJwksKeyResolver =
        new HttpsJwksVerificationKeyResolver(httpsJkws);
    JsonWebSignature jws = new JsonWebSignature();
    jws.setAlgorithmConstraints(new AlgorithmConstraints(
        ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_PSS_USING_SHA256));

	String encodedPayload = Base64Url.encode(body).replace("=", "");
	String[] signatureComponents = signature.split("\\.");
	if (signatureComponents.length != 3) {
		logger.error("Invalid signature: {}", signature);
		return new ResponseEntity<String>("", null, 400);
	}

    String jwsHeader = signatureComponents[0];
	String jwsSignature = signatureComponents[2];
    try {
      jws.setCompactSerialization(jwsHeader + "." + encodedPayload + "." + jwsSignature);
    } catch (JoseException e) {
      logger.error("Error setting compact serialization", e);
      return new ResponseEntity<String>("", null, 500);
    }

    try {
      Key key = httpsJwksKeyResolver.resolveKey(jws, null);
      jws.setKey(key);
    } catch (UnresolvableKeyException e) {
      logger.error("Error resolving key", e);
      return new ResponseEntity<String>("", null, 500);
    }

    try {
      boolean signatureVerified = jws.verifySignature();
      if (!signatureVerified) {
        logger.error("Signature not verified signature: {}, body: {}, key: {}",
                     signature, body, jws.getKey());
        return new ResponseEntity<String>("", null, 500);
      }
    } catch (JoseException e) {
      logger.error("Error verifying signature", e);
      return new ResponseEntity<String>("", null, 500);
    }

    logger.info("Signature verified");
    return new ResponseEntity<String>("", null, 200);
  }
}
