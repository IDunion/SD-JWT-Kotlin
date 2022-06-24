# SD-JWT Implementation in Kotlin

This is a Kotlin implementation of the [Selective Disclosure for JWTs](https://github.com/oauthstuff/draft-selective-disclosure-jwt)
spec using the [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) 
library.

## Checking Out the Implementation

In the [Main.kt](src/main/kotlin/com/yes/sd_jwt/Main.kt) file 
there are two examples that show how the library can be used
on the issuance, wallet and verifier side.

### Running the Examples

If you have Docker installed you can simply run:

1. ``docker build -t sd-jwt .``
2. ``docker run -it --rm sd-jwt``