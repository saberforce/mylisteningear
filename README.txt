=====================================================
OFFLINE HYBRID SIGNATURE INDEPENDENT VERIFICATION KIT
=====================================================

OVERVIEW:
This independent verification tool allows you to cryptographically 
validate hybrid signatures (ECDSA secp256r1 + Post-Quantum Dilithium Level 3) 
100% offline without connecting to any external servers or services.
Ensure you download index.html and main.json into the same directory.

INSTRUCTIONS:
1. Double-click "index.html" to open it in any standard browser 
   (Chrome, Edge, Firefox, or Safari).
2. Paste the 64-character SHA-256 File Hash (Hex) into the File Hash field.
3. Paste the Hybrid Base64 Signature into the Signature field.
4. Paste the Hybrid Base64 Public Key into the Public Key field.
5. Click "Verify Signature".

AUDIT LOG OUTPUT:
- Step 1 checks Classical ECDSA (secp256r1) signature validity.
- Step 2 checks Post-Quantum Dilithium (Level 3) signature validity.
- Both cryptographic primitives must pass for a "TRUE" result.
============================================================

If index.html does not work because of your browser's security, then follow the instructions near the last part of the pdf.
