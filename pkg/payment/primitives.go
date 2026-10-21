// primitives.go holds the payment-industry cryptographic primitives required
// by retail payment standards (PVV, CVV, PIN blocks, ISO 9797 MACs, key check
// values). DES/TDES use here is mandated by the standards themselves; this
// package is the only sanctioned home for it — services must not implement
// these primitives locally.
package payment
