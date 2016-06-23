package me.adamstroud.rxcrypto;

/**
 * TODO
 *
 * @author Adam Stroud &#60;<a href="mailto:adam.stroud@gmail.com">adam.stroud@gmail.com</a>&#62;
 */
public enum SecretKeyAlgorithm {
    AES("AES");

    public final String providerString;

    SecretKeyAlgorithm(String providerString) {
        this.providerString = providerString;
    }
}
