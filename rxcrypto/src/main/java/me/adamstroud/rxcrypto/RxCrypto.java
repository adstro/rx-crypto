/*
 * Copyright 2016 Adam Stroud
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.adamstroud.rxcrypto;

import android.support.annotation.IntRange;
import android.support.annotation.NonNull;

import com.google.common.base.Charsets;

import org.spongycastle.asn1.cms.GCMParameters;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.GCMBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMEncryptedKeyPair;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.PKCS8Generator;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.openssl.jcajce.JcaPKCS8Generator;
import org.spongycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.spongycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.spongycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.spongycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.spongycastle.operator.InputDecryptorProvider;
import org.spongycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import rx.Observable;
import rx.Subscriber;

/**
 * TODO
 *
 * @author Adam Stroud &#60;<a href="mailto:adam.stroud@gmail.com">adam.stroud@gmail.com</a>&#62;
 */
public class RxCrypto {
    static {
        PRNGFixes.apply();
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    private static final int IV_SIZE_BYTES = 16;
    private static final int TAG_LENGTH = 128;
    private static final String SYMMETRIC_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ASYMMETRIC_TRANSFORMATION = "RSA/NONE/OAEPWithSHA1AndMGF1Padding";
    private static final String PBE_TRANSFORMATION = "PBKDF2WithHmacSHA1";
    private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-512";
    private static final int PBE_ITERATIONS = 1000;
    private static final String PKCS8_ENCRYPTION_ALGORITHM = "AES-256-CBC";

    /**
     * TODO
     *
     * @param algorithm
     * @param keyLength
     * @return
     */
    public static Observable<SecretKey> generateSecretKey(@NonNull final String algorithm,
                                                          @IntRange(from=0) final int keyLength) {
        return Observable.create(new Observable.OnSubscribe<SecretKey>() {
            @Override
            public void call(Subscriber<? super SecretKey> subscriber) {
                try {
                    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
                    keyGenerator.init(keyLength, new SecureRandom());
                    SecretKey secretKey = keyGenerator.generateKey();

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(secretKey);
                        subscriber.onCompleted();
                    }
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<SecretKey> generateSecretKey(@NonNull final String algorithm,
                                                          @NonNull final byte[] keyBytes) {
        return Observable.create(new Observable.OnSubscribe<SecretKey>() {
            @Override
            public void call(Subscriber<? super SecretKey> subscriber) {
                try {
                    SecretKey secretKey = SecretKeyFactory
                            .getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
                            .generateSecret(new SecretKeySpec(keyBytes, algorithm));

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(secretKey);
                        subscriber.onCompleted();
                    }
                } catch (Throwable e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> encryptNative(@NonNull final SecretKey secretKey,
                                                   @NonNull final byte[] iv,
                                                   @NonNull final byte[] plaintext,
                                                   @NonNull final String aad) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                try {
                    AEADParameters params =
                            new AEADParameters(new KeyParameter(secretKey.getEncoded()),
                                    TAG_LENGTH,
                                    iv,
                                    aad.getBytes(Charsets.UTF_8));

                    GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
                    gcm.init(true, params);
                    byte[] cipherText = new byte[gcm.getOutputSize(plaintext.length)];
                    int offOut = gcm.processBytes(plaintext, 0, plaintext.length, cipherText, 0);
                    gcm.doFinal(cipherText, offOut);

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(cipherText);
                        subscriber.onCompleted();
                    }
                } catch (InvalidCipherTextException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> encrypt(@NonNull final SecretKey secretKey,
                                             @NonNull final byte[] iv,
                                             @NonNull final byte[] plaintext,
                                             @NonNull final String aad) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                try {
                    Cipher cipher = Cipher.getInstance(SYMMETRIC_TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));
                    cipher.updateAAD(aad.getBytes(Charsets.UTF_8));

                    byte[] cipherText = cipher.doFinal(plaintext);

                    AlgorithmParameters params = cipher.getParameters();
                    GCMParameters gcmParameters = GCMParameters.getInstance(params.getEncoded());

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(cipherText);
                        subscriber.onCompleted();
                    }
                } catch (NoSuchAlgorithmException
                        | NoSuchProviderException
                        | NoSuchPaddingException
                        | IllegalBlockSizeException
                        | BadPaddingException
                        | InvalidKeyException
                        | InvalidAlgorithmParameterException
                        | IOException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> encrypt(@NonNull final PublicKey publicKey,
                                             @NonNull final byte[] plaintext) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                try {
                    Cipher cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    byte[] cipherText = cipher.doFinal(plaintext);

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(cipherText);
                        subscriber.onCompleted();
                    }
                } catch (NoSuchAlgorithmException
                        | NoSuchProviderException
                        | NoSuchPaddingException
                        | IllegalBlockSizeException
                        | BadPaddingException
                        | InvalidKeyException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> decrypt(@NonNull final SecretKey secretKey,
                                             @NonNull final byte[] iv,
                                             @NonNull final byte[] cipherText,
                                             @NonNull final String aad) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {

                try {
                    Cipher cipher = Cipher.getInstance(SYMMETRIC_TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));
                    cipher.updateAAD(aad.getBytes(Charsets.UTF_8));
                    byte[] plainText = cipher.doFinal(cipherText);

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(plainText);
                        subscriber.onCompleted();
                    }
                } catch (NoSuchAlgorithmException
                        | NoSuchProviderException
                        | NoSuchPaddingException
                        | IllegalBlockSizeException
                        | BadPaddingException
                        | InvalidKeyException
                        | InvalidAlgorithmParameterException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> decrypt(@NonNull final PrivateKey privateKey,
                                             @NonNull final byte[] cipherText) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                try {
                    Cipher cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] plainText = cipher.doFinal(cipherText);

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(plainText);
                        subscriber.onCompleted();
                    }
                } catch (Throwable e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    /**
     * TODO
     * @param password
     * @param keyLength
     * @return
     *
     * Based on http://android-developers.blogspot.com/2013/02/using-cryptography-to-store-credentials.html
     */
    public static Observable<SecretKey> generatePasswordBasedSecretKey(@NonNull final char[] password,
                                                                       @IntRange(from = 0) final int keyLength,
                                                                       @NonNull final byte[] salt) {
        return Observable.create(new Observable.OnSubscribe<SecretKey>() {
            @Override
            public void call(Subscriber<? super SecretKey> subscriber) {
                try {
                    // Number of PBKDF2 hardening rounds to use. Larger values increase
                    // computation time. You should select a value that causes computation
                    // to take >100ms.

                    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBE_TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
                    KeySpec keySpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, keyLength);
                    SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(secretKey);
                        subscriber.onCompleted();
                    }
                } catch (Throwable t) {
                    subscriber.onError(t);
                }
            }
        });
    }

    public static Observable<KeyPair> generateKeyPair() {
        return Observable.create(new Observable.OnSubscribe<KeyPair>() {
            @Override
            public void call(Subscriber<? super KeyPair> subscriber) {
                try {
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    keyPairGenerator.initialize(4096, new SecureRandom());
                    KeyPair keyPair = keyPairGenerator.generateKeyPair();

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(keyPair);
                        subscriber.onCompleted();
                    }
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> generateHash(final byte[] input) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                try {
                    MessageDigest messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
                    messageDigest.update(input);
                    byte[] hash = messageDigest.digest();

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(hash);
                        subscriber.onCompleted();
                    }
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<PrivateKey> readPrivateKeyFromPem(@NonNull final String pemContents,
                                                               @NonNull final String password) {
        return Observable.create(new Observable.OnSubscribe<PrivateKey>() {
            @Override
            public void call(Subscriber<? super PrivateKey> subscriber) {
                try {
                    PrivateKey privateKey;
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                    PEMParser pemParser = new PEMParser(new StringReader(pemContents));

                    Object object = pemParser.readObject();
                    if (object instanceof PEMEncryptedKeyPair) {
                        PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) object;
                        PEMKeyPair decryptedKeyPair = encryptedKeyPair.decryptKeyPair(new JcePEMDecryptorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password.toCharArray()));

                        privateKey = converter.getPrivateKey(decryptedKeyPair.getPrivateKeyInfo());
                    } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                        InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .build(password.toCharArray());
                        PKCS8EncryptedPrivateKeyInfo info = (PKCS8EncryptedPrivateKeyInfo) object;

                        privateKey = converter.getPrivateKey(info.decryptPrivateKeyInfo(provider));
                    } else {
                        throw new IllegalArgumentException("No supported key found in PEM contents");
                    }

                    if (!subscriber.isUnsubscribed()) {
                        subscriber.onNext(privateKey);
                        subscriber.onCompleted();
                    }
                } catch (Throwable e) {
                    subscriber.onError(e);
                }
            }
        });
    }

    public static Observable<byte[]> writePrivateKeyToPemWithPkcs8(@NonNull final PrivateKey privateKey,
                                                                   @NonNull final String password) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        StringWriter stringWriter = new StringWriter();
                        JcaPEMWriter writer = new JcaPEMWriter(stringWriter);

                        JceOpenSSLPKCS8EncryptorBuilder builder =
                                new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                                        .setPasssword(password.toCharArray());

                        writer.writeObject(new JcaPKCS8Generator(privateKey, builder.build()).generate());
                        writer.close();

                        if (!subscriber.isUnsubscribed()) {
                            subscriber.onNext(stringWriter.toString().getBytes(Charsets.UTF_8));
                            subscriber.onCompleted();
                        }

                    } catch (Throwable e) {
                        subscriber.onError(e);
                    }
                }
            }
        });
    }

    public static Observable<byte[]> writePrivateKeyToPem(@NonNull final PrivateKey privateKey,
                                                          @NonNull final String password) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        StringWriter stringWriter = new StringWriter();
                        JcaPEMWriter writer = new JcaPEMWriter(stringWriter);

                        JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder(PKCS8_ENCRYPTION_ALGORITHM)
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME);

                        writer.writeObject(privateKey, builder.build(password.toCharArray()));
                        writer.close();

                        if (!subscriber.isUnsubscribed()) {
                            subscriber.onNext(stringWriter.toString().getBytes(Charsets.UTF_8));
                            subscriber.onCompleted();
                        }
                    } catch (Throwable e) {
                        subscriber.onError(e);
                    }
                }
            }
        });
    }

    public static Observable<byte[]> generateIV() {
        return generateRandomBytes(IV_SIZE_BYTES);
    }

    public static Observable<byte[]> generatePbeSalt() {
        return generateRandomBytes(20);
    }

    public static Observable<byte[]> generateSha256Salt() {
        return generateRandomBytes(32);
    }

    private static Observable<byte[]> generateRandomBytes(final int numberOfBytes) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                byte[] randomBytes = new byte[numberOfBytes];

                byte[] test = new SecureRandom().generateSeed(16);

                new SecureRandom().nextBytes(randomBytes);

                if (!subscriber.isUnsubscribed()) {
                    subscriber.onNext(randomBytes);
                    subscriber.onCompleted();
                }
            }
        });
    }
}
