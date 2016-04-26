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

import android.util.Pair;

import org.assertj.core.api.Condition;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import rx.Observable;
import rx.functions.Func1;
import rx.functions.Func2;
import rx.observers.TestSubscriber;

import static org.assertj.core.api.Java6Assertions.assertThat;

/**
 * Test cases for {@link RxCrypto}.
 *
 * @author Adam Stroud &#60;<a href="mailto:adam.stroud@gmail.com">adam.stroud@gmail.com</a>&#62;
 */
public class RxCryptoTest {
    private static final String TAG = RxCryptoTest.class.getSimpleName();
    private static final String ENCODING = "UTF-8";

    @Test
    public void testGenerateSecretKey() throws Exception {
        final String algorithm = "AES";
        final int keySizeInBits = 256;

        TestSubscriber<SecretKey> testSubscriber = new TestSubscriber<>();

        RxCrypto.generateSecretKey(algorithm, keySizeInBits)
                .subscribe(testSubscriber);

        SecretKey secretKey = checkTestSubscriberAndGetValue(testSubscriber);

        assertThat(secretKey)
                .has(new Condition<SecretKey>() {
                    @Override
                    public boolean matches(SecretKey secretKey) {
                        return algorithm.equals(secretKey.getAlgorithm());
                    }})
                .has(new Condition<SecretKey>() {
                    @Override
                    public boolean matches(SecretKey secretKey) {
                        return (keySizeInBits / 8) == secretKey.getEncoded().length;
                    }});
    }

    @Test
    public void testGenerateSecretKeyWithInvalidAlgorithm() throws Exception {
        final String algorithm = "invalidAlgorithm";
        final int keySizeInBits = 256;

        TestSubscriber<SecretKey> testSubscriber = new TestSubscriber<>();

        RxCrypto.generateSecretKey(algorithm, keySizeInBits)
                .subscribe(testSubscriber);

        testSubscriber.awaitTerminalEvent(10, TimeUnit.SECONDS);
        testSubscriber.assertNoValues();
        testSubscriber.assertError(NoSuchAlgorithmException.class);
    }

    @Test
    public void testSymmetricEncryptDecrypt() throws Exception {
        final byte[] plainText = "SecretMessage".getBytes(ENCODING);
        final TestSubscriber<Pair<byte[], SecretKey>> pairTestSubscriber = new TestSubscriber<>();
        final TestSubscriber<byte[]> encryptTestSubscriber = new TestSubscriber<>();

        Observable.zip(RxCrypto.generateIV(),
                RxCrypto.generateSecretKey("AES", 256),
                new Func2<byte[], SecretKey, Pair<byte[], SecretKey>>() {
                    @Override
                    public Pair<byte[], SecretKey> call(byte[] iv, SecretKey secretKey) {
                        return new Pair<>(iv, secretKey);
                    }
                })
                .subscribe(pairTestSubscriber);
        Pair<byte[], SecretKey> resultPair = checkTestSubscriberAndGetValue(pairTestSubscriber);
        final byte[] iv = resultPair.first;
        final SecretKey secretKey = resultPair.second;

        RxCrypto.encrypt(secretKey, iv, RxCrypto.CipherTransformation.GCM, plainText)
                .flatMap(new Func1<byte[], Observable<byte[]>>() {
                    @Override
                    public Observable<byte[]> call(byte[] ciphertext) {
                        return RxCrypto.decrypt(secretKey, iv, RxCrypto.CipherTransformation.GCM, ciphertext);
                    }
                })
                .subscribe(encryptTestSubscriber);

        byte[] resultBytes = checkTestSubscriberAndGetValue(encryptTestSubscriber);
        assertThat(new String(resultBytes, ENCODING)).isEqualTo(new String(plainText, ENCODING));
    }

    @Test
    public void testPbeEncryptionDecryption() throws Exception {
        final String password = "password";
        final String plaintext = "This is a secret message.";
        final TestSubscriber<byte[]> saltTestSubscriber = new TestSubscriber<>();

        RxCrypto.generatePbeSalt().subscribe(saltTestSubscriber);
        final byte[] salt = checkTestSubscriberAndGetValue(saltTestSubscriber);

        final TestSubscriber<SecretKey> encryptionKeyTestSubscriber = new TestSubscriber<>();
        RxCrypto.generatePasswordBasedSecretKey(password.toCharArray(), 256, salt)
                .subscribe(encryptionKeyTestSubscriber);
        SecretKey encryptionKey = checkTestSubscriberAndGetValue(encryptionKeyTestSubscriber);

        TestSubscriber<SecretKey> decryptionKeyTestSubscriber = new TestSubscriber<>();
        RxCrypto.generatePasswordBasedSecretKey(password.toCharArray(), 256, salt)
                .subscribe(decryptionKeyTestSubscriber);
        SecretKey decryptionKey = checkTestSubscriberAndGetValue(decryptionKeyTestSubscriber);

        assertThat(encryptionKey.getEncoded()).isEqualTo(decryptionKey.getEncoded());

        TestSubscriber<byte[]> ivTestSubscriber = new TestSubscriber<>();
        RxCrypto.generateIV().subscribe(ivTestSubscriber);
        byte[] iv = checkTestSubscriberAndGetValue(ivTestSubscriber);

        TestSubscriber<byte[]> cipherTextTestSubscriber = new TestSubscriber<>();
        RxCrypto.encrypt(encryptionKey, iv, RxCrypto.CipherTransformation.GCM, plaintext.getBytes(ENCODING))
                .subscribe(cipherTextTestSubscriber);
        byte[] cipherText = checkTestSubscriberAndGetValue(cipherTextTestSubscriber);

        TestSubscriber<byte[]> plaintextTestSubscriber = new TestSubscriber<>();
        RxCrypto.decrypt(decryptionKey, iv, RxCrypto.CipherTransformation.GCM, cipherText)
                .subscribe(plaintextTestSubscriber);
        byte[] plaintextBytes = checkTestSubscriberAndGetValue(plaintextTestSubscriber);

        assertThat(new String(plaintextBytes, ENCODING)).isEqualTo(plaintext);
    }

    @Test
    public void testGenerateKeyPair() throws Exception {
        final TestSubscriber<KeyPair> testSubscriber = new TestSubscriber<>();
        RxCrypto.generateKeyPair()
                .subscribe(testSubscriber);

        KeyPair keyPair = checkTestSubscriberAndGetValue(testSubscriber);

        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("RSA");
        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");

    }

    @Test
    public void testKeyPairEncryptDecrypt() throws Exception {
        final TestSubscriber<KeyPair> keyPairTestSubscriber = new TestSubscriber<>();
        final String plainText = "Secret Message";

        RxCrypto.generateKeyPair().subscribe(keyPairTestSubscriber);
        KeyPair keyPair = checkTestSubscriberAndGetValue(keyPairTestSubscriber);

        final TestSubscriber<byte[]> ivTestSubscriber = new TestSubscriber<>();
        RxCrypto.generateIV().subscribe(ivTestSubscriber);
        byte[] iv = checkTestSubscriberAndGetValue(ivTestSubscriber);

        final TestSubscriber<byte[]> encryptionTestSubscriber = new TestSubscriber<>();
        RxCrypto.encrypt(keyPair.getPublic(),
                RxCrypto.CipherTransformation.RSA,
                plainText.getBytes(ENCODING))
                .subscribe(encryptionTestSubscriber);
        byte[] cipherText = checkTestSubscriberAndGetValue(encryptionTestSubscriber);

        final TestSubscriber<byte[]> decryptionTestSubscriber = new TestSubscriber<>();
        RxCrypto.decrypt(keyPair.getPrivate(), RxCrypto.CipherTransformation.RSA, cipherText)
                .subscribe(decryptionTestSubscriber);

         byte[] plaintextBytes = checkTestSubscriberAndGetValue(decryptionTestSubscriber);

        assertThat(new String(plaintextBytes, ENCODING)).isEqualTo(plainText);
    }

    @Test
    public void testGenerateHash() throws Exception {
        final String message = "This is a message.";
        final TestSubscriber<byte[]> testSubscriber = new TestSubscriber<>();

        RxCrypto.generateHash(message.getBytes("UTF-8"))
                .subscribe(testSubscriber);
        byte[] messageHash = checkTestSubscriberAndGetValue(testSubscriber);

        assertThat(Hex.toHexString(messageHash)).isEqualToIgnoringCase("B5AEE900D6C80E9EAE27939A9" +
                "548C73288FFE49E0B529F2A64408336B5A4944F6BCCA34EE34ABEB593C688D06B243724DDE133194" +
                "7B74CC83D7A80DDBD569CCD");
    }

    private <T> T checkTestSubscriberAndGetValue(TestSubscriber<T> testSubscriber) {
        testSubscriber.awaitTerminalEvent(10, TimeUnit.SECONDS);
        testSubscriber.assertNoErrors();
        testSubscriber.assertValueCount(1);
        testSubscriber.assertCompleted();
        return testSubscriber.getOnNextEvents().get(0);
    }
}