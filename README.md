[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/PBKDF2.NET/blob/main/LICENSE)
# PBKDF2.NET
A .NET implementation of [PBKDF2](https://www.rfc-editor.org/rfc/rfc8018#section-5.2) with HMAC-SHA-2.

> **Warning**
> 
> Do **NOT** use this algorithm. It is **NOT** strong or well designed. It requires a [high number of iterations](https://tobtu.com/minimum-password-settings/) today. Use [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) instead.