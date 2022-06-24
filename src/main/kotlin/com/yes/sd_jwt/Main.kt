package com.yes.sd_jwt

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import kotlinx.serialization.Serializable

@Serializable
data class LoginCredential(val given_name: String = "", val family_name: String = "", val email: String = "")
@Serializable
data class Address(val street_address: String = "", val locality: String = "", val region: String = "", val country: String = "")
@Serializable
data class IdCredential(val given_name: String = "", val family_name: String = "", val email: String = "", val birthday: String = "", val nicknames: Set<String> = setOf(), val address: Address = Address())


fun main(args: Array<String>) {
    val verifier = "http://verifier.example.com"
    val issuer = "http://issuer.example.com"

    val issuerKey = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("IssuerKey")
        .generate()
    val holderKey = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("HolderKey")
        .generate()
    val holderPublicKey = holderKey.toPublicJWK()

    val trustedIssuers = mutableMapOf<String, String>()
    trustedIssuers[issuer] = issuerKey.toPublicJWK().toJSONString()
    println("Trusted Issuers: $trustedIssuers\n")

    // First example
    println("====================================================")
    println("                     Issuer                         ")
    println("====================================================")
    val claims0 = LoginCredential("Alice", "Wonderland", "alice@example.com")
    println("Claims for credential0: $claims0\n")

    val credential0 = createCredential(claims0, null, issuer, issuerKey)
    println("Credential0: $credential0\n")

    println("====================================================")
    println("                     Wallet                         ")
    println("====================================================")
    val releaseClaims0 = LoginCredential("disclose", "", "disclose")
    val presentation0 = createPresentation(credential0, releaseClaims0, verifier, "12345", null)
    println("Presentation0: $presentation0\n")

    println("====================================================")
    println("                     Verifier                       ")
    println("====================================================")
    val verifiedLoginCredential = verifyPresentation<LoginCredential>(presentation0, trustedIssuers,"12345", verifier)
    println("Verified Login Credential: $verifiedLoginCredential\n")

    // Second example
    println("====================================================")
    println("                     Issuer                         ")
    println("====================================================")
    val claims1 = IdCredential("Alice", "Wonderland", "alice@example.com", "1940-01-01", setOf("A", "B"), Address("123 Main St", "Anytown", "Anystate", "US"))
    println("Claims for credential1: $claims1\n")

    val credential1 = createCredential(claims1, holderPublicKey, issuer, issuerKey, 1)
    println("Credential1: $credential1\n")

    println("====================================================")
    println("                     Wallet                         ")
    println("====================================================")
    val releaseClaims1 = IdCredential("disclose", "disclose", "", "", setOf("disclose"), Address("disclose", "disclose", "", ""))
    val presentation1 = createPresentation(credential1, releaseClaims1, verifier, "12345", holderKey)
    println("Presentation1: $presentation1\n")

    println("====================================================")
    println("                     Verifier                       ")
    println("====================================================")
    val verifiedIdCredential = verifyPresentation<IdCredential>(presentation1, trustedIssuers,"12345", verifier)
    println("Verified Id Credential: $verifiedIdCredential")
}