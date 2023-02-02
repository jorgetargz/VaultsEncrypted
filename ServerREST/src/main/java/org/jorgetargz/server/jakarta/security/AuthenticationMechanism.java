package org.jorgetargz.server.jakarta.security;

import com.nimbusds.jose.util.X509CertUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.server.dao.excepciones.DatabaseException;
import org.jorgetargz.server.dao.excepciones.NotFoundException;
import org.jorgetargz.server.dao.excepciones.UnauthorizedException;
import org.jorgetargz.server.domain.services.ServicesUsers;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.server.jakarta.common.Constantes;
import org.jorgetargz.utils.modelo.User;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Set;

@Log4j2
@ApplicationScoped
public class AuthenticationMechanism implements HttpAuthenticationMechanism {

    private final KeyPair keyPair;
    private final JWTBlackList jwtBlackList;
    private final ServicesUsers servicesUsers;

    @Inject
    public AuthenticationMechanism(KeyPair keyPair, JWTBlackList jwtBlackList, ServicesUsers servicesUsers) {
        this.keyPair = keyPair;
        this.jwtBlackList = jwtBlackList;
        this.servicesUsers = servicesUsers;
    }

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest httpServletRequest,
                                                HttpServletResponse httpServletResponse
            , HttpMessageContext httpMessageContext) {

        CredentialValidationResult credentialValidationResult = null;

        String header = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            String[] headerFields = header.split(Constantes.WHITE_SPACE);
            if (headerFields.length == 2) {
                String tipo = headerFields[0];
                String valor = headerFields[1];
                if (tipo.equals(Constantes.BEARER)) {
                    credentialValidationResult = jwtAuthentication(httpServletResponse, valor);
                } else if (tipo.equals(Constantes.CERTIFICATE)) {
                    credentialValidationResult = certificateAuthentication(valor);
                    // Si la firma es válida, se crea un JWT y se añade al header de la respuesta
                    if (credentialValidationResult.getStatus() == CredentialValidationResult.Status.VALID) {
                        httpServletResponse.addHeader(HttpHeaders.AUTHORIZATION,
                                String.format(Constantes.BEARER_AUTH, createJWT(credentialValidationResult)));
                    }
                }
            }
        }

        return getAuthenticationStatus(httpServletRequest, httpMessageContext, credentialValidationResult);
    }

    private CredentialValidationResult certificateAuthentication(String valor) {
        String[] authenticationFields = valor.split(":");
        String usernameBase64 = authenticationFields[0];
        String randomStringBase64 = authenticationFields[1];
        String signatureBase64 = authenticationFields[2];

        String username = new String(Base64.getUrlDecoder().decode(usernameBase64));
        byte[] randomString = Base64.getUrlDecoder().decode(randomStringBase64);
        byte[] signature = Base64.getUrlDecoder().decode(signatureBase64);
        User user;
        try {
            user = servicesUsers.scGet(username);
        } catch (ValidationException | DatabaseException | NotFoundException e) {
            log.error(e.getMessage(), e);
            return CredentialValidationResult.INVALID_RESULT;
        }
        if (user.getCertificate() == null) {
            return CredentialValidationResult.INVALID_RESULT;
        }
        String certificateBase64 = user.getCertificate();
        X509Certificate certificate = X509CertUtils.parse(Base64.getUrlDecoder().decode(certificateBase64));
        PublicKey publicKey = certificate.getPublicKey();
        // Se comprueba la firma del randomString con la clave pública del certificado
        try {
            Signature sign = Signature.getInstance("SHA256WithRSA");
            sign.initVerify(publicKey);
            sign.update(randomString);
            if (!sign.verify(signature)) {
                return CredentialValidationResult.INVALID_RESULT;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error(e.getMessage(), e);
            return CredentialValidationResult.NOT_VALIDATED_RESULT;
        }
        return new CredentialValidationResult(user.getUsername(), Set.of(user.getRole()));
    }

    private String createJWT(CredentialValidationResult credentialValidationResult) {

        JwtClaims claims = new JwtClaims();
        claims.setIssuer(Constantes.NEWSPAPERS_API);
        claims.setAudience(Constantes.CLIENTS);
        claims.setExpirationTimeMinutesInTheFuture(Constantes.EXPIRATION_TIME_MINUTES_IN_THE_FUTURE);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(Constantes.NOT_BEFORE_MINUTES_IN_THE_PAST);
        claims.setSubject(Constantes.API_AUTH);
        claims.setClaim(Constantes.NOMBRE, credentialValidationResult.getCallerPrincipal().getName());
        Set<String> rolesSet = credentialValidationResult.getCallerGroups();
        List<String> rolesList = List.copyOf(rolesSet);
        claims.setStringListClaim(Constantes.ROLES, rolesList);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(keyPair.getPrivate());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private CredentialValidationResult jwtAuthentication(HttpServletResponse httpServletResponse, String jwt) {
        CredentialValidationResult credentialValidationResult = CredentialValidationResult.INVALID_RESULT;
        try {
            credentialValidationResult = getCredentialFromJWT(jwt);
        } catch (InvalidJwtException e) {
            if (e.hasExpired()) {
                httpServletResponse.addHeader(Constantes.TOKEN_EXPIRED, Constantes.TRUE);
            }
        } catch (UnauthorizedException e) {
            httpServletResponse.addHeader(Constantes.TOKEN_IN_BLACK_LIST, Constantes.TRUE);
        }
        return credentialValidationResult;
    }

    private CredentialValidationResult getCredentialFromJWT(String jwt) throws InvalidJwtException {
        CredentialValidationResult credentialValidationResult = null;

        if (jwtBlackList.getJWTBlackList().contains(jwt)) {
            throw new UnauthorizedException(Constantes.TOKEN_IN_BLACK_LIST);
        }

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(Constantes.SECONDS_OF_ALLOWED_CLOCK_SKEW)
                .setRequireSubject()
                .setExpectedIssuer(Constantes.NEWSPAPERS_API)
                .setExpectedAudience(Constantes.CLIENTS)
                .setVerificationKey(keyPair.getPublic())
                .setJwsAlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256)
                .build();

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            List<String> rolesList = jwtClaims.getStringListClaimValue(Constantes.ROLES);
            Set<String> rolesSet = Set.copyOf(rolesList);
            String username = jwtClaims.getClaimValueAsString(Constantes.NOMBRE);
            credentialValidationResult = new CredentialValidationResult(username, rolesSet);
        } catch (MalformedClaimException e) {
            log.error(e.getMessage(), e);
        }
        return credentialValidationResult;
    }

    private AuthenticationStatus getAuthenticationStatus(HttpServletRequest httpServletRequest,
                                                         HttpMessageContext httpMessageContext,
                                                         CredentialValidationResult credentialValidationResult) {

        if (credentialValidationResult != null) {

            if (credentialValidationResult.getStatus() == CredentialValidationResult.Status.VALID) {
                return httpMessageContext.notifyContainerAboutLogin(credentialValidationResult);
            }

            if (credentialValidationResult.getStatus() == CredentialValidationResult.Status.INVALID) {
                httpServletRequest.setAttribute(Constantes.ERROR_LOGIN, Constantes.INVALID_CREDENTIALS);
            } else if (credentialValidationResult.getStatus() == CredentialValidationResult.Status.NOT_VALIDATED) {
                httpServletRequest.setAttribute(Constantes.ERROR_LOGIN, Constantes.SERVER_ERROR);
            }

        } else {
            httpServletRequest.setAttribute(Constantes.ERROR_LOGIN, Constantes.LOGIN_REQUIRED);
        }

        return httpMessageContext.doNothing();
    }
}