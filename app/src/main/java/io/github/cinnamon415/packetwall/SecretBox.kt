package io.github.cinnamon415.packetwall

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts small secrets (the upstream proxy password) with AES-256-GCM. On the device the key is
 * created in and never leaves the Android Keystore ([keystore]); the sealed form is
 * base64(12-byte IV + ciphertext with tag).
 */
class SecretBox(private val key: () -> SecretKey) {
    fun seal(plain: String): String {
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.ENCRYPT_MODE, key())
        return Base64.getEncoder().encodeToString(c.iv + c.doFinal(plain.toByteArray()))
    }

    /** null when the value cannot be decrypted (corrupt, or the key is gone after a device restore). */
    fun open(sealed: String): String? = try {
        val b = Base64.getDecoder().decode(sealed)
        require(b.size > IV_BYTES) { "too short" }
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, b, 0, IV_BYTES))
        String(c.doFinal(b, IV_BYTES, b.size - IV_BYTES))
    } catch (e: Exception) {
        Log.w("SecretBox", "cannot decrypt: $e")
        null
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val ALIAS = "packetwall-secrets"
        private const val PROVIDER = "AndroidKeyStore"

        fun keystore() = SecretBox {
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            (ks.getKey(ALIAS, null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
                init(
                    KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build()
                )
                generateKey()
            }
        }
    }
}
