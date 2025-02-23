use anchor_lang::prelude::*;

use ark_bn254::{Fq, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::One;
use num_bigint::BigUint;
use solana_program::alt_bn128::prelude::*;
use solana_program::big_mod_exp::big_mod_exp;
use tiny_keccak::{Hasher, Keccak};

declare_id!("55q9EhHs3kVsH3dZKbBojec9ao1kJb56g1D7jLoNyCEp");

fn fq_from_big_uint(n: BigUint) -> Fq {
    let mut bytes = [0u8; 32];
    n.to_bytes_be()
        .iter()
        .rev()
        .enumerate()
        .for_each(|(i, &b)| bytes[i] = b);
    Fq::from_le_bytes_mod_order(&bytes)
}

static P_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x97, 0x81, 0x6a,
    0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];
static Q_BYTES: [u8; 32] = [
    0x0c, 0x19, 0x13, 0x9c, 0xb8, 0x4c, 0x68, 0x0a, 0x6e, 0x14, 0x11, 0x6d, 0xa0, 0x60, 0x56, 0x17, 0x65, 0xe0, 0x5a,
    0xa4, 0x5a, 0x1c, 0x72, 0xa3, 0x4f, 0x08, 0x23, 0x05, 0xb6, 0x1f, 0x3f, 0x52,
];

// the nG2zzz is the negation of the G2 generator point
//     "11559732032986387107991004021392285783925812861821192530917403151452391805634",
static nG2x1: [u8; 32] = [
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25, 0xf1, 0xaa, 0x49,
    0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
];
//     "10857046999023057135944570762232829481370756359578518086990519993285655852781",
static nG2x0: [u8; 32] = [
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79, 0x67, 0x43, 0x22,
    0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
];
//     "17805874995975841540914202342111839520379459829704422454583296818431106115052",
static nG2y1: [u8; 32] = [
    0x27, 0x5d, 0xc4, 0xa2, 0x88, 0xd1, 0xaf, 0xb3, 0xcb, 0xb1, 0xac, 0x09, 0x18, 0x75, 0x24, 0xc7, 0xdb, 0x36, 0x39,
    0x5d, 0xf7, 0xbe, 0x3b, 0x99, 0xe6, 0x73, 0xb1, 0x3a, 0x07, 0x5a, 0x65, 0xec,
];

// "13392588948715843804641432497768002650278120570034223513918757245338268106653",
static nG2y0: [u8; 32] = [
    0x1d, 0x9b, 0xef, 0xcd, 0x05, 0xa5, 0x32, 0x3e, 0x6d, 0xa4, 0xd4, 0x35, 0xf3, 0xb6, 0x17, 0xcd, 0xb3, 0xaf, 0x83,
    0x28, 0x5c, 0x2d, 0xf7, 0x11, 0xef, 0x39, 0xc0, 0x15, 0x71, 0x82, 0x7f, 0x9d,
];

// test vectors
static SK_BYTES: [u8; 32] = [
    0x0c, 0x3b, 0x68, 0x7e, 0xa7, 0x1d, 0x49, 0x85, 0x84, 0xcb, 0x64, 0x01, 0x6a, 0x56, 0x47, 0xcd, 0x95, 0x6f, 0xa1,
    0x2c, 0xc0, 0x6c, 0x24, 0x01, 0xcf, 0xf1, 0xbc, 0xee, 0xd8, 0x6f, 0xb0, 0xf6,
];
// "8378816085881533471915855765377395720650519250900991714910570838142371337484",
static PKX0: [u8; 32] = [
    0x12, 0x86, 0x3d, 0xe9, 0x9c, 0xc0, 0x03, 0x7a, 0xc6, 0xd0, 0x04, 0x0c, 0x76, 0xb7, 0x07, 0x02, 0x73, 0x9e, 0x01,
    0xd4, 0xd7, 0x38, 0x93, 0xed, 0x9f, 0xfc, 0xbf, 0x6a, 0x6b, 0x01, 0x95, 0x0c,
];

// "12790415566273137204438980474676206431551668194861774000289116208318672938344",
static PKX1: [u8; 32] = [
    0x1c, 0x47, 0x1e, 0x60, 0xe1, 0xf7, 0x9d, 0xe8, 0x49, 0xd0, 0xb1, 0xe0, 0x0c, 0x3e, 0xc2, 0xeb, 0x52, 0x5b, 0xd5,
    0xa5, 0x38, 0x64, 0x70, 0x16, 0x3d, 0x0d, 0xcd, 0x83, 0x28, 0x56, 0x25, 0x68,
];

// "19990703290207056186001361313522144773565207870437521135189959374985874088302",
static PKY0: [u8; 32] = [
    0x2c, 0x32, 0x56, 0x4c, 0x01, 0x8b, 0x5e, 0x59, 0x86, 0x17, 0x56, 0x5d, 0xa8, 0x28, 0x55, 0xa1, 0x43, 0x92, 0xa6,
    0x01, 0x45, 0x1c, 0xbd, 0x12, 0xd9, 0x04, 0xc6, 0x02, 0xa3, 0x9f, 0xa1, 0x6e,
];
// "4358342334887501838847343362140356079440147357795966237968340896425437333463",
static PKY1: [u8; 32] = [
    0x09, 0xa2, 0xbb, 0xfd, 0xf4, 0x23, 0x20, 0x70, 0x14, 0x4a, 0x06, 0x04, 0xf2, 0x4a, 0x15, 0xb2, 0xd0, 0xe5, 0xaa,
    0x58, 0x35, 0x11, 0x53, 0xec, 0x22, 0xc4, 0x0c, 0x39, 0x71, 0xa4, 0x87, 0xd7,
];

// verify signature: compariing the pairings: E(sig, pk) ==? E(hash, G2)
// all slice must be of size 32
// NOTE: this function can panic if input parameters are not correct (e.g. not on curve)
fn verify(
    sigx: &[u8],
    sigy: &[u8],
    pkx0: &[u8],
    pkx1: &[u8],
    pky0: &[u8],
    pky1: &[u8],
    hashx: &[u8],
    hashy: &[u8],
) -> bool {
    // TODO: return false if any of the input is not 32 bytes slice
    let mut input2 = [0u8; 384];
    input2[0..32].copy_from_slice(&sigx);
    input2[32..64].copy_from_slice(&sigy);
    input2[64..96].copy_from_slice(&nG2x1);
    input2[96..128].copy_from_slice(&nG2x0);
    input2[128..160].copy_from_slice(&nG2y1);
    input2[160..192].copy_from_slice(&nG2y0);
    input2[192..224].copy_from_slice(&hashx);
    input2[224..256].copy_from_slice(&hashy);
    input2[256..288].copy_from_slice(&pkx1);
    input2[288..320].copy_from_slice(&pkx0);
    input2[320..352].copy_from_slice(&pky1);
    input2[352..384].copy_from_slice(&pky0);
    let res = alt_bn128_pairing(input2.as_slice()).unwrap();
    res[31] == 1
}

// hash_to_g1_point hashes a message to a G1 point
// first it uses keccak256 to hash the msg into 32 bytes, interpreted as a big integer in BE as x,
// then it calculates y^2 = x^3 + 3, doing a custom sqrt; compute y if it exists
// there is 50% chance that no such y exists, in that case we increment x and try again.
// Keep incrementing x until a suitable (x,y) pair is found to satisfy y^2 = x^3 + 3 (on the curve)
// and return (x,y) as a G1 point (the hased point)
// this could take as many as 16 tries; but should take 2 tries on average.
pub fn hash_to_g1_point(msg: &[u8]) -> Option<G1Affine> {
    let three = Fq::from(3u64);
    let one = Fq::one();
    let mut hasher = Keccak::v256();
    hasher.update(msg);
    let mut hashed_result = [0u8; 32];
    hasher.finalize(&mut hashed_result);
    let big_int = BigUint::from_bytes_be(&hashed_result);

    let mut x = fq_from_big_uint(big_int);
    let mut y = x;
    y.square_in_place();
    y *= x;
    y += three;

    let mut iter = 0;
    loop {
        iter += 1;
        // sqrt(y) -- if sqrt of y exists, then it must be y^((p+1)/4) mod p
        // according to fermat's little theorem; compute and check.
        let p = BigUint::from_bytes_be(&P_BYTES);
        let y_bytes = y.into_bigint().to_bytes_be();

        let y2_bytes = big_mod_exp(y_bytes.as_slice(), Q_BYTES.as_slice(), p.to_bytes_be().as_slice());
        let y2 = BigUint::from_bytes_be(&y2_bytes);
        let y2_fq = fq_from_big_uint(y2);
        let y22 = y2_fq.square();
        if y22 == y {
            let hash_point = G1Projective::new(x, y2_fq, Fq::one()).into_affine();
            return Some(hash_point);
        }
        if iter > 20 {
            return None;
        }
        // increment x and try again
        x += one;
    }
}

#[program]
pub mod solanabls {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    // this is a step-by-step exploration for cross-checking with Solidity/Go impl of BLS verification routine
    // and benchmarking for CU cost
    // Keep it here for reference only
    pub fn compute(ctx: Context<Compute>) -> Result<()> {
        let three = Fq::from(3u64);

        let message = "Hello BLS".as_bytes();
        let hash_point = hash_to_g1_point(&message).unwrap();

        // now sign: secretkey * message hash
        let sk_int = BigUint::from_bytes_be(&SK_BYTES);
        // alt_bn128_multiplication input is 96 bytes
        // fill the first 32 bytes of input with the hash_point.x in big endian
        // fill the second 32 bytes of input with the hash_point.y in big endian
        // fill the third 32 bytes of input with the sk_int in big endian
        let x_bytes = hash_point.x.into_bigint().to_bytes_be();
        let y_bytes = hash_point.y.into_bigint().to_bytes_be();
        let sk_bytes = sk_int.to_bytes_be();
        let mut input = [0u8; 96];
        for i in 0..32 {
            input[i] = x_bytes[i];
            input[i + 32] = y_bytes[i];
            input[i + 64] = sk_bytes[i];
        }
        let sig = alt_bn128_multiplication(input.as_slice()).unwrap();

        // verify signature: compariing the pairings: E(sig, pk) ==? E(hash, G2)
        let res = verify(&sig[..32], &sig[32..64], &PKX0, &PKX1, &PKY0, &PKY1, &x_bytes, &y_bytes);
        assert!(res, "signature verification failed");
        msg!("BLS(BN254) signature hash, sign and verification success!");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct Compute {}

#[derive(Accounts)]
pub struct Verify {}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{Fr, G2Affine, G2Projective};
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger256;
    use ark_std::ops::Mul;
    use num_bigint::BigUint;
    use num_traits::Num;

    use rust_bls_bn254::{hash_to_curve, key_gen, sign, verify};

    #[test]
    fn test_generic() {
        let sk_str = "5532719355993668376817313988550233634227690018686483329169046691728862458102";
        let sk_bigint = BigUint::from_str_radix(sk_str, 10).unwrap();
        let bytes = sk_bigint.to_bytes_le();
        assert!(bytes.len() == 32, "size of sk bytes should be 256");
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate().take(4) {
            let mut limb_bytes = [0u8; 8];
            // Copy each chunk into an 8-byte array (zero-padding if necessary).
            for (j, b) in chunk.iter().enumerate() {
                limb_bytes[j] = *b;
            }
            limbs[i] = u64::from_le_bytes(limb_bytes);
        }
        let bigint = BigInteger256::new(limbs);

        println!("reconstructed bigint256 sk: {}", bigint);
        let sk = Fr::new(bigint);
        println!("reconstructed Fr sk: {}", sk);

        let pubkey = G2Projective::from(G2Affine::generator()).mul(sk).into_affine();
        println!("pubkey: {:?}", pubkey);

        let message = "Hello BLS".as_bytes();
        let hashed = hash_to_curve(message);
        println!("hashed: {:?}", hashed);

        let sig = sign(sk, &message.to_vec()).unwrap();

        let res = verify(pubkey, &message.to_vec(), sig);
        assert!(res, "verify failed");
    }
}
