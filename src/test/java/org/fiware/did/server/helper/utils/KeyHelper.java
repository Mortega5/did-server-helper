package org.fiware.did.server.helper.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

public final class KeyHelper {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private KeyHelper() {
    }

    public static KeyPair generateAndStoreKey(
            String type,
            Path privateKeyPath,
            Path certificatePath,
            Integer rsaKeySize,
            String ecCurve,
            String subjectDn,
            int daysValidity
    ) throws Exception {
        if (privateKeyPath == null) {
            throw new IllegalArgumentException("privateKeyPath cannot be null");
        }

        KeyPair kp;
        if ("EC".equalsIgnoreCase(type)) {
            String curve = ecCurve == null ? "secp256r1" : ecCurve;
            kp = generateEcKeyPair(curve);
        } else { // default RSA
            int size = rsaKeySize == null ? 2048 : rsaKeySize;
            kp = generateRsaKeyPair(size);
        }

        writePrivateKeyPem(kp.getPrivate(), privateKeyPath);

        if (certificatePath != null) {
            String subj = subjectDn == null ? "CN=generated" : subjectDn;
            int days = daysValidity <= 0 ? 365 : daysValidity;
            X509Certificate cert = generateSelfSignedCertificate(kp, subj, days);
            writeCertificatePem(cert, certificatePath);
        }

        return kp;
    }

    public static KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static KeyPair generateEcKeyPair(String curveName) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        kpg.initialize(spec, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn, int daysValid)
            throws Exception {
        String sigAlg = defaultSignatureAlgorithmFor(keyPair);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60);
        Date notAfter = new Date(now + daysValid * 24L * 60L * 60L * 1000L);
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X500Name subject = new X500Name(subjectDn);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    public static String defaultSignatureAlgorithmFor(KeyPair keyPair) {
        String alg = keyPair.getPrivate().getAlgorithm();
        return switch (alg == null ? "" : alg.toUpperCase(java.util.Locale.ROOT)) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            default -> "SHA256withRSA";
        };
    }

    public static String privateKeyToPem(PrivateKey privateKey) throws IOException {
        try (StringWriter sw = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(privateKey);
            pemWriter.flush();
            return sw.toString();
        }
    }

    public static String certificateToPem(X509Certificate certificate) throws IOException {
        try (StringWriter sw = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            return sw.toString();
        }
    }

    public static void writePrivateKeyPem(PrivateKey privateKey, Path path) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, privateKeyToPem(privateKey));
    }

    public static void writeCertificatePem(X509Certificate certificate, Path path) throws IOException {
        Files.createDirectories(path.getParent());

    }
}