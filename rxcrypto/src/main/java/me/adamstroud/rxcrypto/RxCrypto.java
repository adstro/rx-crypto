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
import android.util.Log;

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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

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

    private static final String PROVIDER = "SC";
    private static final int IV_SIZE_BYTES = 16;

    public enum CipherTransformation {
        GCM("AES/GCM/NoPadding"),
        CBC("AES/CBC/PKCS7Padding"),
        RSA("RSA/NONE/OAEPWithSHA512AndMGF1Padding");

        private final String stringValue;

        private CipherTransformation(String stringValue) {
            this.stringValue = stringValue;
        }

        public String getStringValue() {
            return stringValue;
        }
    }

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
                if (!subscriber.isUnsubscribed()) {
                    try {
                        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, PROVIDER);
                        keyGenerator.init(keyLength, new SecureRandom());

                        subscriber.onNext(keyGenerator.generateKey());
                        subscriber.onCompleted();
                    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }
                }
            }
        });
    }

    public static Observable<byte[]> encrypt(@NonNull final SecretKey secretKey,
                                             @NonNull final byte[] iv,
                                             @NonNull final CipherTransformation cipherTransformation,
                                             @NonNull final byte[] plaintext) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        Cipher cipher = Cipher.getInstance(cipherTransformation.getStringValue(), PROVIDER);
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

                        subscriber.onNext(cipher.doFinal(plaintext));
                    } catch (NoSuchAlgorithmException
                            | NoSuchProviderException
                            | NoSuchPaddingException
                            | IllegalBlockSizeException
                            | BadPaddingException
                            | InvalidKeyException
                            | InvalidAlgorithmParameterException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }
                }
            }
        });
    }

    public static Observable<byte[]> encrypt(@NonNull final PublicKey publicKey,
                                             @NonNull final CipherTransformation cipherTransformation,
                                             @NonNull final byte[] plaintext) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        Cipher cipher = Cipher.getInstance(cipherTransformation.getStringValue(), PROVIDER);
                        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                        subscriber.onNext(cipher.doFinal(plaintext));
                    } catch (NoSuchAlgorithmException
                            | NoSuchProviderException
                            | NoSuchPaddingException
                            | IllegalBlockSizeException
                            | BadPaddingException
                            | InvalidKeyException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }
                }
            }
        });
    }

    public static Observable<byte[]> decrypt(@NonNull final SecretKey secretKey,
                                             @NonNull final byte[] iv,
                                             @NonNull final CipherTransformation cipherTransformation,
                                             @NonNull final byte[] cipherText) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        Cipher cipher = Cipher.getInstance(cipherTransformation.getStringValue(), PROVIDER);
                        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
                        subscriber.onNext(cipher.doFinal(cipherText));
                    } catch (NoSuchAlgorithmException
                            | NoSuchProviderException
                            | NoSuchPaddingException
                            | IllegalBlockSizeException
                            | BadPaddingException
                            | InvalidKeyException
                            | InvalidAlgorithmParameterException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }
                }
            }
        });
    }

    public static Observable<byte[]> decrypt(@NonNull final PrivateKey privateKey,
                                             @NonNull final CipherTransformation cipherTransformation,
                                             @NonNull final byte[] cipherText) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        Cipher cipher = Cipher.getInstance(cipherTransformation.getStringValue(), PROVIDER);
                        cipher.init(Cipher.DECRYPT_MODE, privateKey);
                        subscriber.onNext(cipher.doFinal(cipherText));
                    } catch (NoSuchAlgorithmException
                            | NoSuchProviderException
                            | NoSuchPaddingException
                            | IllegalBlockSizeException
                            | BadPaddingException
                            | InvalidKeyException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }
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
                if (!subscriber.isUnsubscribed()) {
                    try {
                        // Number of PBKDF2 hardening rounds to use. Larger values increase
                        // computation time. You should select a value that causes computation
                        // to take >100ms.
                        final int iterations = 1000;

                        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", PROVIDER);
                        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);

                        Log.d("TIME", "Before = " + System.currentTimeMillis());
                        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
                        Log.d("TIME", "After = " + System.currentTimeMillis());
                        subscriber.onNext(secretKey);
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }
                }
            }
        });
    }

    public static Observable<KeyPair> generateKeyPair() {
        return Observable.create(new Observable.OnSubscribe<KeyPair>() {
            @Override
            public void call(Subscriber<? super KeyPair> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER);
                        keyPairGenerator.initialize(4096, new SecureRandom());
                        subscriber.onNext(keyPairGenerator.generateKeyPair());
                    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
                    }

                }
            }
        });
    }

    public static Observable<byte[]> generateHash(final byte[] input) {
        return Observable.create(new Observable.OnSubscribe<byte[]>() {
            @Override
            public void call(Subscriber<? super byte[]> subscriber) {
                if (!subscriber.isUnsubscribed()) {
                    try {
                        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512", PROVIDER);
                        messageDigest.update(input);

                        subscriber.onNext(messageDigest.digest());
                    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                        subscriber.onError(e);
                    } finally {
                        subscriber.onCompleted();
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
                if (!subscriber.isUnsubscribed()) {
                    byte[] randomBytes = new byte[numberOfBytes];
                    new SecureRandom().nextBytes(randomBytes);
                    subscriber.onNext(randomBytes);
                    subscriber.onCompleted();
                }
            }
        });
    }
}
