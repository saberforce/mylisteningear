import 'dart:html';
import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';
import 'package:dilithium_crypto/dilithium_crypto.dart';

void main() {
  final verifyBtn = querySelector('#verifyBtn');
  final output = querySelector('#output');

  verifyBtn?.onClick.listen((_) {
    output?.text = "Running Independent Verification...\n--------------------------------------------------\n";

    // 1. Fetch and sanitize inputs from the HTML fields
    final fileHashHex = (querySelector('#fileHash') as InputElement).value?.trim().replaceAll(RegExp(r'\s+'), '') ?? '';
    final signatureBase64 = (querySelector('#signature') as TextAreaElement).value?.replaceAll(RegExp(r'\s+'), '') ?? '';
    final publicKeyBase64 = (querySelector('#publicKey') as TextAreaElement).value?.replaceAll(RegExp(r'\s+'), '') ?? '';

    if (fileHashHex.isEmpty || signatureBase64.isEmpty || publicKeyBase64.isEmpty) {
      output?.text = "[ERROR] Please fill in all fields.";
      return;
    }

    try {
      // 2. Decode Envelopes
      final Uint8List hybridSignature = base64Decode(signatureBase64);
      final Uint8List hybridPublicKey = base64Decode(publicKeyBase64);
      final Uint8List rawHashBytes = Uint8List.fromList(hex.decode(fileHashHex));
      
      output?.appendText("[+] Payload Byte Length      : ${rawHashBytes.length} bytes\n");
      output?.appendText("[+] Hybrid Public Key Length : ${hybridPublicKey.length} bytes\n");
      output?.appendText("[+] Hybrid Signature Length  : ${hybridSignature.length} bytes\n\n");

      // 3. Slice the Hybrid Data
      final Uint8List ecdsaPubKeyBytes = hybridPublicKey.sublist(0, 65);
      final Uint8List pqcPubKeyBytes = hybridPublicKey.sublist(65);
      final Uint8List ecdsaSigBytes = hybridSignature.sublist(0, 64);
      final Uint8List pqcSigBytes = hybridSignature.sublist(64);

      // 4. Verify Classical ECDSA
      final curve = ECCurve_secp256r1();
      final q = curve.curve.decodePoint(ecdsaPubKeyBytes);
      final publicKey = ECPublicKey(q!, curve);
      final verifier = ECDSASigner(null, HMac(SHA256Digest(), 64));
      verifier.init(false, PublicKeyParameter<ECPublicKey>(publicKey));
      
      final r = BigInt.parse(hex.encode(ecdsaSigBytes.sublist(0, 32)), radix: 16);
      final s = BigInt.parse(hex.encode(ecdsaSigBytes.sublist(32, 64)), radix: 16);
      
      final bool isEcdsaValid = verifier.verifySignature(rawHashBytes, ECSignature(r, s));
      output?.appendText("[${isEcdsaValid ? '✓' : 'X'}] Step 1: Classical ECDSA (secp256r1) -> ${isEcdsaValid ? 'PASSED' : 'FAILED'}\n");

      // 5. Verify Post-Quantum Dilithium
      final pqcPublicKeyObj = DilithiumPublicKey.deserialize(DilithiumParameterSpec.LEVEL3, pqcPubKeyBytes);
      
      // We test both raw binary and UTF-8 string payload formats just to be safe
      final bool testRaw = Dilithium.verify(pqcPublicKeyObj, pqcSigBytes, rawHashBytes);
      final bool testUtf8 = Dilithium.verify(pqcPublicKeyObj, pqcSigBytes, Uint8List.fromList(utf8.encode(fileHashHex)));
      
      final bool isPqcValid = testRaw || testUtf8;
      output?.appendText("[${isPqcValid ? '✓' : 'X'}] Step 2: Quantum Dilithium (Level 3) -> ${isPqcValid ? 'PASSED' : 'FAILED'}\n\n");

      // 6. Final Result
      output?.appendText("==================================================\n");
      if (isEcdsaValid && isPqcValid) {
        output?.appendText("RESULT: TRUE - HYBRID SIGNATURE FULLY VALIDATED\n");
      } else {
        output?.appendText("RESULT: FALSE - VERIFICATION FAILED\n");
      }
      output?.appendText("==================================================");

    } catch (e) {
      output?.appendText("\n[!] Error during execution: $e");
    }
  });
}