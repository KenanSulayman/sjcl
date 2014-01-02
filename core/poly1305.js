/** @fileOverview Poly1305 implementation.
 *
 * Poly1305 is a MAC by D. J. Bernstein: http://cr.yp.to/mac.html
 *
 * Poly1305(key, c) builds a checksum with a polynom:
 *    csum = (c_1*r'^q + ... + c_q*r'^1) mod (2^130 - 5),
 * and encrypts that csum with s:
 *    mac = (csum + s) mod 2^128
 * c_i are derived from the input message c (split into 128-bit/16-byte blocks,
 * (little-endian) deserialize to number, add 2^blocklen as padding).
 * r' is r with some bits clamped to 0.
 * r and s are 16 bytes long (128 bits) and concat(r, s) is the key, c is the message (byte aligned).
 *
 * Poly1305-AES(r, k, n, c) = Poly1305(concat(r, AES-128_k(n)), c)
 *
 * Poly1305 uses little endian to (de)serialize numbers.
 *
 * @author Stefan Bühler
 */

sjcl.misc.poly1305 = (function() {
  var p1305 = sjcl.bn.prime.p1305, bn = sjcl.bn, radix = p1305.prototype.radix, bA = sjcl.bitArray;
  var bit129ndx = Math.floor(128 / radix);
  var bit129value = 1 << (128 % radix);

  // in place
  function byteswap(r) {
    var i, v;
    for (i = 0; i < r.length; ++i) {
      v = r[i];
      r[i] = (v >>> 24) | ((v >>> 8) & 0xff00) | ((v & 0xff00) << 8) | ((v & 0xff) << 24);
    }
    return r;
  }

  // convert (up to) 4 little endian 32-bit unsigned words in a[offset..offset+4] to a bignumber of class cls
  // input can end in partial big-endian word if it is byte aligned
  function bits128ToNum(a, offset, cls) {
    return cls.fromBits(byteswap(a.slice(offset, offset + 4)).reverse());
  }

  /**
   * Context for a Poly1305 operation in progress. Can be called as normal function too,
   * with the data to authenticate as second parameter
   * @param {bitArray} [key]  256-bit key (128-bit "r" for the polynom, 128-bit "s" to encrypt ("+" mod 2^128) the resulting tag)
   * @param {bitArray} [data] (only in non-constructor mode) the data to authenticate.
   * @return {poly1305|bitArray}
   *
   * @constructor
   */
  function poly1305(key, data) {
    if (!(this instanceof poly1305)) {
      return (new poly1305(key)).update(data).finalize();
    }

    if (8 != key.length) throw new sjcl.exception.invalid("invalid Poly1305 key size");

    key[0] &= ~0xf0;
    key[1] &= ~(0x30000f0);
    key[2] &= ~(0x30000f0);
    key[3] &= ~(0x30000f0);
    this._r = bits128ToNum(key, 0, p1305);
    this._s = bits128ToNum(key, 4, bn);
    this._h = new p1305(0);
    this._buffer = null;
  }

  /**
   * Input several words to the message to verify.
   * @param {bitArray} [data] the data to authenticate.
   * @return this
   */
  poly1305.prototype.update = function(data) {
    var h = this._h, r = this._r;
    if (this._buffer) {
      data = bA.concat(this._buffer, data);
      this._buffer = null;
    }

    var i, l = Math.floor(bA.bitLength(data) / 32) & ~0x3, ci;
    for (i = 0; i < l; i += 4) {
      ci = bits128ToNum(data, i, p1305);
      ci.limbs[bit129ndx] = (ci.limbs[bit129ndx] || 0) + bit129value;
      h.addM(ci).cnormalize();
      h = h.mul(r);
    }
    if (i < data.length) {
      this._buffer = data.slice(i);
    }
    this._h = h;

    return this;
  };

  /**
   * Calculate final authentication tag for message; doesn't modify the state.
   * @return {bitArray} 128-bit tag
   */
  poly1305.prototype.finalize = function() {
    var h = this._h.copy(), r = this._r, s = this._s;
    if (this._buffer) {
      var data = this._buffer;
      var l = bA.bitLength(data);
      var ci = bits128ToNum(data, 0, p1305);
      var ndx = Math.floor(l / radix);
      ci.limbs[ndx] = (ci.limbs[ndx] || 0) + (1 << (l % radix));
      h.addM(ci).cnormalize();
      h = h.mul(r);
    }
    h = new bn(h.fullReduce());
    h.addM(s);
    return byteswap(h.toBits(128)).reverse();
  };

  /**
   * Verifies given tag authenticates the message; doesn't modify the state.
   * Uses constant time comparision.
   * @param {bitArray} [tag] 128-bit tag to compare with
   */
  poly1305.prototype.verify = function(tag) {
    var t = this.finalize();
    return bA.equal(t, tag);
  };

  return poly1305;
})();

sjcl.misc.poly1305aes = (function() {
  /**
   * Context for a Poly1305(-AES) operation in progress. Can be called as normal function too,
   * with the data to authenticate as fourth parameter
   * @param {bitArray} [r]     128-bit "r"
   * @param {bitArray} [key]   128-bit AES key
   * @param {bitArray} [nonce] 128-bit nonce
   * @param {bitArray} [data]  (only in non-constructor mode) the data to authenticate.
   * @return {poly1305|bitArray}
   *
   * @constructor (returns a sjcl.misc.poly1305 object)
   */
  function poly1305aes(r, key, nonce, data) {
    var isConstructor = false;
    if (this instanceof poly1305aes) {
      isConstructor = true;
    }
    if (4 != key.length || 4 != nonce.length) throw new sjcl.exception.invalid("invalid Poly1305-AES key/nonce size");
    var s = new sjcl.cipher.aes(key).encrypt(nonce);
    if (isConstructor) {
      return new sjcl.misc.poly1305(r.concat(s));
    } else {
      return sjcl.misc.poly1305(r.concat(s), data);
    }
  }

  return poly1305aes;
})();
